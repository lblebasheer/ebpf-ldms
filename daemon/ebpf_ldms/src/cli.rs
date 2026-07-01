use std::env;

use clap::Parser;
use log::warn;

#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = env!("CARGO_PKG_DESCRIPTION"), long_about = None)]
pub struct EbpfLdms {
    /// Name of LDMS stream to which messages are published
    #[arg(id="stream",long,default_value_t = String::from("nersc"),value_name="STREAM")]
    pub stream: String,
    /// Average message rate limit for an individual producer in messages/interval (see --interval)
    #[arg(
        id = "msglimit",
        long,
        default_value_t = 2,
        value_name = "MSGPERPERIOD"
    )]
    pub msglimit: u64,
    /// Length of time interval over which message limits are calculated. In seconds
    #[arg(id = "interval", long, default_value_t = 1, value_name = "INTERVAL")]
    pub interval: u64,
    /// Hostname or IP address of LDMS daemon
    #[arg(id="host",long,default_value_t = String::from("localhost"),value_name="HOST")]
    pub host: String,
    /// TCP Port of LDMS daemon
    #[arg(id="port",long,default_value_t = String::from("60003"),value_name="PORT")]
    pub port: String,
    /// Authentication method when connecting to LDMS daemon
    #[arg(id="authentication",long,default_value_t = String::from("none"),value_name="none|munge")]
    pub authentication: String,
    /// Set "hostname" field to this value in published messages
    #[arg(id="hostname",long,default_value_t = String::from("localhost"),value_name="HOSTNAME")]
    pub hostname: String,
    /// File to which logs are written in addition to the console
    #[arg(id="logfile",long,default_value_t = String::from("/var/log/ebpf_ldms.log"),value_name="LOGFILE")]
    pub logfile: String,
}

pub trait ValidateClap {
    fn parse_ratelimit(&mut self);
}

impl ValidateClap for EbpfLdms {
    fn parse_ratelimit(&mut self) {
        (self.msglimit, self.interval) = match (self.msglimit, self.interval) {
            (0, 0) => {
                warn!("Invalid msglimit and interval. Setting to 1 msg/second");
                (1, 1)
            }
            (0, j @ 1..) => {
                warn!("Invalid msglimit. Setting to 1 msg/{j} second(s)");
                (1, j)
            }
            (i @ 1.., 0) => {
                warn!("Invalid interval. Setting to 1 second");
                (i, 1)
            }
            (i @ 1.., j @ 1..) => (i, j),
        };
    }
}
