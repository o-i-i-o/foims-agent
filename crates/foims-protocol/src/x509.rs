//! 轻量 x509 辅助（agent 与服务端共用的证书剩余寿命解析）。
//!
//! 服务端续期端点校验请求证书剩余寿命、agent 端触发续期检查均依赖
//! 同一解析口径。本文件为主仓 `foims-common/src/x509.rs` 的受控副本，
//! 修改解析口径必须双侧同步，详见 crate 文档。

use x509_parser::pem::parse_x509_pem;

/// 解析 PEM 证书的剩余寿命：(剩余天数, 失效时刻 UNIX 秒)。
///
/// 剩余天数按整 86400 秒折算（已过期返回负数）；PEM 解析失败或时间
/// 溢出时报错。使用系统时钟，调用方自行考虑时钟偏差的影响。
pub fn cert_remaining(cert_pem: &str) -> Result<(i64, i64), String> {
    let (_, pem_block) = parse_x509_pem(cert_pem.trim().as_bytes())
        .map_err(|e| format!("解析证书 PEM 失败: {e}"))?;
    let parsed = pem_block
        .parse_x509()
        .map_err(|e| format!("解析 X.509 证书失败: {e}"))?;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default();
    let not_after = parsed.validity().not_after.timestamp();
    Ok(((not_after - now_secs) / 86_400, not_after))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    /// 自签一张指定有效期的测试证书（rcgen，仅用于剩余寿命解析验证）：
    /// not_before 提前 `backdate_days` 天，not_after 为当前时刻 + `valid_days` 天。
    fn self_signed(backdate_days: i64, valid_days: i64) -> String {
        let key = KeyPair::generate().unwrap_or_else(|e| panic!("生成密钥失败: {e}"));
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "foims-x509-test");
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(backdate_days);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(valid_days);
        let cert = params
            .self_signed(&key)
            .unwrap_or_else(|e| panic!("自签失败: {e}"));
        cert.pem()
    }

    #[test]
    fn 剩余寿命_未过期取整向下() {
        // 90 天有效期，剩余应落在 89-90 天（按整 86400 秒向下取整）
        let (days, not_after) = cert_remaining(&self_signed(1, 90)).unwrap_or((-1, -1));
        assert!(
            (89..=90).contains(&days),
            "剩余天数应按整 86400 秒向下取整: {days}"
        );
        assert!(not_after > 0, "失效时刻应为正 UNIX 秒");
    }

    #[test]
    fn 剩余寿命_已过期为负数() {
        // not_after 已过去 1 天：剩余天数应为 -1（整数除法向零截断仍为负）
        let (days, _) = cert_remaining(&self_signed(3, -1)).unwrap_or((1, 0));
        assert!(days < 0, "已过期证书剩余天数应为负数: {days}");
    }

    #[test]
    fn 剩余寿命_非pem输入报错() {
        assert!(cert_remaining("not a pem").is_err());
        assert!(cert_remaining("-----BEGIN CERTIFICATE-----\nbroken\n").is_err());
    }
}
