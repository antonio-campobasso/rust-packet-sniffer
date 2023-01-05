use clap::Parser;
use packet_sniffer::*;

use std::io::stdin;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Enables guided mode
    #[clap(short, long, action, value_name = "guided mode")]
    guided: bool,

    /// Network interface to perform the sniffing operation.
    #[clap(value_parser, value_name = "network interface")]
    network_interface: Option<String>,

    /// Time interval between report writings.
    #[clap(value_parser, value_name = "time interval")]
    time_interval: Option<usize>,

    /// Path of the file(without extension) in which the report will be written.
    #[clap(value_parser, value_name = "output file")]
    file_name: Option<String>,

    /// Filter to apply to sniffed packets
    #[clap(short, long("filter"), value_parser, value_name = "filter")]
    filter_string: Option<String>,
}

pub struct Params {
    pub network_interface: String,
    pub time_interval: usize,
    pub file_name: String,
    pub filter: String,
}

#[derive(Debug)]
pub enum ParamErrors {
    MissingNetworkInterface,
    MissingTimeInterval,
    MissingFileName,
}

pub fn get_params() -> Result<Params, ParamErrors> {
    let mut network_interface;
    let time_interval: usize;
    let mut file_name;
    let filter;

    let cli = Args::parse();

    if cli.guided {
        let mut buffer = String::new();
        let devices = list_all_devices();

        // Network interface selection
        loop {
            buffer.clear();

            println!("Select network interface from the following: ");
            let interfaces: Vec<String> = devices
                .as_ref()
                .unwrap()
                .iter()
                .map(|device| device.name.clone())
                .collect();

            interfaces
                .iter()
                .for_each(|interface| println!("- {}", interface));

            stdin().read_line(&mut buffer).unwrap();
            network_interface = buffer.trim().to_string();

            if interfaces.contains(&network_interface) {
                break;
            }
            println!("Interface not present in the list")
        }

        // Time interval
        loop {
            buffer.clear();

            println!("Insert time interval between report production: ");
            stdin().read_line(&mut buffer).unwrap();

            if let Ok(val) = buffer.trim().parse() {
                time_interval = val;
                break;
            }

            println!("Insert a valid number")
        }

        // File name
        loop {
            buffer.clear();

            println!("Insert file name for the report: ");
            stdin().read_line(&mut buffer).unwrap();
            file_name = buffer.trim().to_string();

            if !file_name.is_empty() {
                break;
            }
        }

        buffer.clear();

        // Filter
        println!("Insert packet filter string (Using BPF syntax): ");
        stdin().read_line(&mut buffer).unwrap();

        filter = buffer.trim().to_string();
    } else {
        if cli.network_interface.is_none() {
            return Err(ParamErrors::MissingNetworkInterface);
        }

        if cli.time_interval.is_none() {
            return Err(ParamErrors::MissingTimeInterval)
        }

        if cli.file_name.is_none() {
            return Err(ParamErrors::MissingFileName)
        }

        network_interface = cli.network_interface.unwrap().clone();

        time_interval = cli.time_interval.unwrap();
        file_name = cli.file_name.unwrap();
        match cli.filter_string {
            Some(f) => filter = f,
            None => filter = "".to_string(),
        }
    }

    let print_filter = match filter.as_str() {
        "" => "(None)".to_string(),
        f => f.to_string(),
    };

    println!(
        "<---Parameters--->\nNetwork interface: {}\nTime Interval: {}\nFile name: {}.csv\nFilter: {}\n<---------------->",
        network_interface, time_interval, file_name, print_filter
    );

    return Ok(Params {
        network_interface,
        time_interval,
        file_name,
        filter,
    });
}
