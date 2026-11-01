//! 采集器实现集合。
//!
//! 每个文件对应 node_exporter 的一个同名采集器；`build_defaults` 返回
//! 默认启用集合（默认开关状态对齐原版，随移植进度逐步扩充）。

pub mod arp;
pub mod bonding;
pub mod boottime;
pub mod conntrack;
pub mod cpu;
pub mod cpufreq;
pub mod diskstats;
pub mod dmi;
pub mod edac;
pub mod entropy;
pub mod filefd;
pub mod filesystem;
pub mod hwmon;
pub mod kernel_hung;
pub mod loadavg;
pub mod meminfo;
pub mod netdev;
pub mod netstat;
pub mod os;
pub mod pressure;
pub mod schedstat;
pub mod selinux;
pub mod sockstat;
pub mod softnet;
pub mod stat;
pub mod textfile;
pub mod thermal_zone;
pub mod time;
pub mod udp_queues;
pub mod uname;
pub mod vmstat;
pub mod watchdog;

use foims_agent_core::collector::Collector;

/// 构建默认启用的采集器实例集合（按名称字母序，输出顺序稳定便于对照）。
pub fn build_defaults() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(arp::ArpCollector::default()),
        Box::new(bonding::BondingCollector::default()),
        Box::new(boottime::BootTimeCollector::default()),
        Box::new(conntrack::ConntrackCollector::default()),
        Box::new(cpu::CpuCollector::default()),
        Box::new(cpufreq::CpufreqCollector::default()),
        Box::new(diskstats::DiskstatsCollector::default()),
        Box::new(dmi::DmiCollector::default()),
        Box::new(edac::EdacCollector::default()),
        Box::new(entropy::EntropyCollector::default()),
        Box::new(filefd::FileFdCollector::default()),
        Box::new(filesystem::FilesystemCollector::default()),
        Box::new(hwmon::HwmonCollector::default()),
        Box::new(kernel_hung::KernelHungCollector::default()),
        Box::new(loadavg::LoadavgCollector::default()),
        Box::new(meminfo::MeminfoCollector::default()),
        Box::new(netdev::NetdevCollector::default()),
        Box::new(netstat::NetstatCollector::default()),
        Box::new(os::OsCollector::default()),
        Box::new(pressure::PressureStatsCollector::default()),
        Box::new(schedstat::SchedstatCollector::default()),
        Box::new(selinux::SelinuxCollector::default()),
        Box::new(sockstat::SockstatCollector::default()),
        Box::new(softnet::SoftnetCollector::default()),
        Box::new(stat::StatCollector::default()),
        Box::new(textfile::TextFileCollector::default()),
        Box::new(thermal_zone::ThermalZoneCollector::default()),
        Box::new(time::TimeCollector::default()),
        Box::new(udp_queues::UdpQueuesCollector::default()),
        Box::new(uname::UnameCollector),
        Box::new(vmstat::VmstatCollector::default()),
        Box::new(watchdog::WatchdogCollector::default()),
    ]
}
