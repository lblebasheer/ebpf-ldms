use clap::Parser;

#[derive(Parser)]
#[command(name = "ebpf_streamer")]
#[command(author = "Ershaad Basheer <ebasheer@lbl.gov>")]
#[command(version = "0.3")]
#[command(about = "Stream count of slow function calls to LDMS", long_about = None)]
pub struct EbpfStreamer {
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
    pub msglimit: u32,
    /// Length of time interval over which message limits are calculated. In seconds
    #[arg(id = "interval", long, default_value_t = 1, value_name = "INTERVAL")]
    pub interval: u32,
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
}
