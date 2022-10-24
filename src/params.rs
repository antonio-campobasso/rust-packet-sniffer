use packet_sniffer::*;
use clap::Parser;

use std::{
    io::stdin,
};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Enables guided mode
    #[clap(short, long, action, value_name = "guided mode")]
    guided: bool,

    /// Network interface to perform the sniffing operation. Defaults to the first interface found.
    #[clap(value_parser, value_name = "network interface")]
    network_interface: Option<String>,

    /// Time interval between report writings. Defaults to 10 seconds.
    #[clap(value_parser, value_name = "time interval")]
    time_interval: Option<usize>,

    /// Path of the file in which the report will be written. Defaults to "./report.txt".
    #[clap(value_parser, value_name = "output file")]
    file_name: Option<String>,

    /// Filter to apply to sniffed packets
    #[clap(value_parser, value_name = "filter")]
    filter_string: Option<String>,
}

pub struct Params {
    pub network_interface: String,
    pub time_interval: usize,
    pub file_name: String,
    pub filter: String,
}

#[derive(Debug)]
pub enum Error {
    NoDevicesError,
    ParseError,
    WrongFilterFormat,
    WrongNameFormat,
    OpeningError,
}

const DEFAULT_TIME_INTERVAL: usize = 10;
const DEFAULT_FILE_NAME: &str = "/report.txt";
const DEFAULT_FILTER_STRING: &str = "not ip6 and not igmp";

pub fn get_params() -> Result<Params, Error> {
    let network_interface;
    let time_interval;
    let file_name;
    let filter;

    let cli = Args::parse();

    if cli.guided {
        let mut buffer = String::new();
        let devices = list_all_devices();

        // Network interface selection
        println!("Select network interface from the following: ");
        devices
            .unwrap()
            .iter()
            .for_each(|device| println!("- {}", device.name));

        stdin().read_line(&mut buffer).unwrap();
        network_interface = buffer.trim().to_string();

        buffer.clear();

        // Time interval
        println!("Insert time interval between report production: ");
        stdin().read_line(&mut buffer).unwrap();

        if let Ok(val) = buffer.trim().parse() {
            time_interval = val;
        } else {
            return Err(Error::ParseError);
        }

        buffer.clear();

        // File name
        println!("Insert file name for the report: ");
        stdin().read_line(&mut buffer).unwrap();
        file_name = buffer.trim().to_string();

        buffer.clear();

        // Filter
        println!("Insert packet filter string: ");
        stdin().read_line(&mut buffer).unwrap();

        filter = buffer.trim().to_string();

        return Ok(Params {
            network_interface,
            time_interval,
            file_name,
            filter,
        });
    }

    match cli.network_interface {
        Some(interface) => network_interface = interface,
        None => {
            network_interface = match list_all_devices() {
                Ok(devices) => match devices.first() {
                    Some(first_device) => {
                        let interface = first_device.name.clone();
                        println!("Interface: {}", interface);
                        interface
                    }
                    None => return Err(Error::NoDevicesError),
                },
                Err(e) => {
                    match e {
                        NetworkInterfaceError::CaptureDeviceOpeningError(_) => return Err(Error::OpeningError),
                        NetworkInterfaceError::WrongNameFormat(_) => return Err(Error::WrongNameFormat),
                        NetworkInterfaceError::FilterError(_) => return Err(Error::WrongFilterFormat),
                        NetworkInterfaceError::NoDevicesError(_) => return Err(Error::NoDevicesError),
                    }
                },
            }
        }
    }

    match cli.time_interval {
        Some(interval) => time_interval = interval,
        None => {
            time_interval = {
                println!("Time interval: {}", DEFAULT_TIME_INTERVAL);
                DEFAULT_TIME_INTERVAL
            }
        }
    }

    match cli.file_name {
        Some(name) => file_name = name,
        None => {
            file_name = {
                println!("File name: {}", DEFAULT_FILE_NAME);
                DEFAULT_FILE_NAME.to_string()
            }
        }
    }

    match cli.filter_string {
        Some(f) => filter = f,
        None => {
            filter = {
                println!("Filter: {}", DEFAULT_FILTER_STRING);
                DEFAULT_FILTER_STRING.to_string()
            }
        }
    }

    return Ok(Params {
        network_interface,
        time_interval,
        file_name,
        filter,
    });
}
