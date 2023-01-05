use packet_sniffer::*;
mod params;

use std::{
    io::stdin,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
    thread::{self, sleep},
    time::Duration,
};

use crate::params::get_params;

fn main() {
    // Threads
    let mut threads = vec![];

    // Shared variables
    let report_collector = Arc::new(Mutex::new(ReportCollector::new()));
    let running_cvar = Arc::new((Mutex::new(true), Condvar::new()));
    let stop = Arc::new(Mutex::new(false));

    // Command line variables
    let params = get_params();

    // Thread variables
    let report_collector_t = report_collector.clone();
    let running_cvar_t = running_cvar.clone();
    let stop_t = stop.clone();

    // Thread #1 -> Packet acquisition
    threads.push(thread::spawn(move || {
        match CaptureDevice::new(params.network_interface, Some(params.filter)) {
            Ok(mut capture) => {
                loop {
                    match capture.next_packet() {
                        Ok(packet) => {
                            let (lock, cvar) = &*running_cvar_t;

                            // Pause condvar
                            let _guard =
                                cvar.wait_while(lock.lock().unwrap(), |running| *running == false);

                            let stop = stop_t.lock().unwrap();
                            if *stop {
                                break;
                            }

                            //println!("Pacchetto Inserito : {:?} - {}", packet.ci, packet.cd); // DEBUG
                            let mut rep = report_collector_t.lock().unwrap();
                            rep.add_packet(packet);
                        }
                        Err(e) => match e {
                            ParsingError::NotSupported(s) | ParsingError::PacketParsingError(s) => {
                                println!("Error: {}", s);
                            }
                        },
                    };
                }
            }
            Err(e) => match e {
                NetworkInterfaceError::CaptureDeviceOpeningError(e)
                | NetworkInterfaceError::WrongNameFormat(e)
                | NetworkInterfaceError::FilterError(e)
                | NetworkInterfaceError::NoDevicesError(e) => {
                    println!("Error: {}", e);
                    let mut stop = stop_t.lock().unwrap();
                    *stop = true;
                }
            },
        }
        println!("Capture connection terminated, type anything to stop the program");
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
                    | ReportError::FooterWritingError(e) => {
                        println!("Error: {}", e);
                        let mut stop = stop_t.lock().unwrap();
                        *stop = true;
                    }
                }
                break;
            } else {
                println!("Report updated");
            }
        }
        println!("Report manager thread terminated, type anything to stop the program");
    }));

    let mut s = String::new();
    println!("Acquisition started, type 'help' or 'h' to see available commands.");
    loop {
        s.clear();
        stdin()
            .read_line(&mut s)
            .expect("Acquisition error in command reading.");

        let (lock, cvar) = &*running_cvar;
        let mut running = lock.lock().unwrap();
        let mut stop = stop.lock().unwrap();

        match s.trim().to_lowercase().as_str() {
            "resume" | "r" => {
                *running = true;
                println!("Sniffing in process, type `pause` or `p` to pause the program and `stop` or `s` to stop it");
                cvar.notify_all();
            }
            "pause" | "p" => {
                *running = false;
                println!(
                    "Sniffing paused, type 'resume' or `r` to unpause or `stop` or `s` to stop it"
                );
                cvar.notify_all();
            }
            "stop" | "s" => {
                *stop = true;

                *running = true;
                println!("Program stopped");
                cvar.notify_all();
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
        };

        if *stop {
            break;
        }
    }

    // NOTE: non ho bisogno di join sui thread
    println!("Program Terminated");
}
