use packet_sniffer::*;
mod params;

use std::{
    io::stdin,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
    thread::{self, sleep},
    time::Duration,
};

use clap::Parser;

use crate::params::get_params;

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

fn main() {
    // Threads
    let mut threads = vec![];

    // Shared variables
    let report_collector = Arc::new(Mutex::new(ReportCollector::new()));
    let running_cvar = Arc::new((Mutex::new(true), Condvar::new()));
    let stop = Arc::new(Mutex::new(false));

    // Command line variables
    let params = match get_params() {
        Ok(params) => params,
        Err(e) => {
            match e {
                params::Error::NoDevicesError => {
                    println!("No capture devices found");
                },
                params::Error::ParseError => {
                    println!("Parsing error");
                },
                params::Error::WrongFilterFormat => {
                    println!("Wrong filter passed");
                },
                params::Error::WrongNameFormat => {
                    println!("Wrong name of interface");
                },
                params::Error::OpeningError => {
                    println!("Error in connection opening");
                },
            };
            return;
        },
    };

    // Thread variables
    let report_collector_t = report_collector.clone();
    let running_cvar_t = running_cvar.clone();
    let stop_t = stop.clone();

    // Thread #1 -> Packet acquisition
    threads.push(thread::spawn(move || {
        match CaptureDevice::new(params.network_interface, Some(params.filter)) {
            Ok(mut capture) => {
                while let Ok(packet) = capture.next_packet() {
                    let (lock, cvar) = &*running_cvar_t;

                    // Pause condvar
                    let _guard = cvar.wait_while(lock.lock().unwrap(), |running| *running == false);

                    let stop = stop_t.lock().unwrap();
                    if *stop {
                        break;
                    }

                    //println!("Pacchetto Inserito : {:?} - {}", packet.ci, packet.cd); // DEBUG
                    let mut rep = report_collector_t.lock().unwrap();
                    rep.add_packet(packet);
                }
                println!("Capture connection terminated.");
            }
            Err(e) => {
                match e {
                    NetworkInterfaceError::CaptureDeviceOpeningError(e)
                    | NetworkInterfaceError::WrongNameFormat(e)
                    | NetworkInterfaceError::FilterError(e)
                    | NetworkInterfaceError::NoDevicesError(e) => println!("{}", e),
                }
            }
        }
    }));

    // Thread variables
    let report_collector_t = report_collector.clone();
    let running_cvar_t = running_cvar.clone();
    let stop_t = stop.clone();

    // Thread #2 -> Report generation
    threads.push(thread::spawn(move || {
        loop {
            sleep(Duration::from_secs(params.time_interval as u64));

            let (lock, cvar) = &*running_cvar_t;

            // Pause condvar
            let _guard = cvar.wait_while(lock.lock().unwrap(), |running| *running == false);

            let stop = stop_t.lock().unwrap();

            if *stop {
                break;
            }

            let rep = report_collector_t.lock().unwrap();
            if let Err(err) = rep.produce_report_to_file(PathBuf::from(params.file_name.clone())) {
                match err {
                    ReportError::CreationFileError(e)
                    | ReportError::HeaderWritingError(e)
                    | ReportError::ReportWritingError(e)
                    | ReportError::FooterWritingError(e) => println!("{}", e),
                }
                break;
            }
        }
        println!("Report manager thread terminated");
    }));

    let mut s = String::new();
    println!("Acquisition started, type 'help' to see available commands.");
    loop {
        s.clear();
        stdin()
            .read_line(&mut s)
            .expect("Acquisition error in command reading.");

        let (lock, cvar) = &*running_cvar;
        let mut running = lock.lock().unwrap();

        match s.trim().to_lowercase().as_str() {
            "resume" | "r" => {
                *running = true;
                println!("Sniffing in process");
                cvar.notify_all();
            }
            "pause" | "p" => {
                *running = false;
                println!("Sniffing paused, type 'resume' to unpause");
                cvar.notify_all();
            }
            "stop" | "s" => {
                let mut stop = stop.lock().unwrap();
                *stop = true;

                *running = true;
                println!("Stopped");
                cvar.notify_all();
                break;
            }
            "help" | "h" => {
                println!(
                    "- Pause (p)     => Pauses packet acquisition and report generation.
- Resume (r)    => Resumes packet acquisition and report generation.
- Stop (s)      => Stops the program.
- Help (h)      => Shows line commands. "
                )
            }
            any => {
                println!("Wrong command: {}", any)
            }
        }
    }

    // NOTE: non ho bisogno di join sui thread
}
