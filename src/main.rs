use packet_sniffer::*;
use pcap::ConnectionStatus;

use std::{
    io::stdin,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
    thread::{self, sleep},
    time::Duration,
};

use clap::Parser;

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
    #[clap(short, long, value_parser, value_name = "filter")]
    filter_string: Option<String>,
}

enum Error {
    NoDevicesError,
    AcquisitionError(String),
    CaptureError,
    LockError(String),
}

const DEFAULT_TIME_INTERVAL: usize = 10;
const DEFAULT_FILE_NAME: &str = "/report.txt";
const DEFAULT_FILTER_STRING: &str = "not ip6 and not igmp";

fn main() {
    // Threads
    let mut threads = vec![];

    // Command line variables
    let mut network_interface = "".to_string();
    let mut time_interval = DEFAULT_TIME_INTERVAL;
    let mut file_name = DEFAULT_FILE_NAME.to_string();
    let mut filter = DEFAULT_FILTER_STRING.to_string();

    // Shared variables
    let report_collector = Arc::new(Mutex::new(ReportCollector::new()));
    let running_cvar = Arc::new((Mutex::new(true), Condvar::new()));
    let stop = Arc::new(Mutex::new(false));
    // NOTE: non posso usare STOP come stato perchè altrimenti si rischia il deadlock

    // Parameters handling
    if let Err(_) = command_line_acquisition(
        &mut network_interface,
        &mut time_interval,
        &mut file_name,
        &mut filter,
    ) {
        panic!();
    }

    // Thread variables
    let report_collector_t = report_collector.clone();
    let running_cvar_t = running_cvar.clone();
    let stop_t = stop.clone();

    // Thread #1 -> Packet acquisition
    threads.push(thread::spawn(move || {
        let mut capture = CaptureDevice::new(network_interface, Some(filter));
        // ERR: network interface or filter could be erroneous
        // CaptureError
        while let Ok(packet) = capture.next_packet() {
            let (lock, cvar) = &*running_cvar_t;

            // Pause condvar
            let _guard = cvar.wait_while(lock.lock().unwrap(), |running| *running == false);

            match stop_t.lock() {
                Ok(stop) => {
                    if *stop {
                        break;
                    }
                },
                Err(e) => {
                    // Poison error on Lock "stop" detected in Thread #1
                    todo!()
                },
            }
            

            match report_collector_t.lock() {
                Ok(mut rep) => rep.add_packet(packet),
                Err(_) => {
                    // Poison error on Lock "report_collector" detected in Thread #1
                    todo!()
                },
            }

            //println!("Pacchetto Inserito : {:?} - {}", packet.ci, packet.cd); // DEBUG
            let mut rep = report_collector_t.lock().unwrap(); //ERR: sistema
            rep.add_packet(packet); //ERR: sistema
        }
        println!("Capture connection terminated.");
    }));

    // Thread variables
    let report_collector_t = report_collector.clone();
    let running_cvar_t = running_cvar.clone();
    let stop_t = stop.clone();

    // Thread #2 -> Report generation
    threads.push(thread::spawn(move || {
        loop {
            sleep(Duration::from_secs(time_interval as u64));
            // NOTE: può capitare che il comando STOP venga inviato durante lo sleep
            // in questo caso il programma non può terminare finchè non scade il timer, un po' uno spreco
            // TODO: considera di usare un thread che ha solo un timer(loop con sleep)
            // che pilota un flag/condvar. Al posto della sleep qui sopra si potrebbe usare una condvar che controlla
            // se il timer è scaduto oppure se è stato ricevuto il comando STOP

            let (lock, cvar) = &*running_cvar_t;

            // Pause condvar
            let _guard = cvar.wait_while(lock.lock().unwrap(), |running| *running == false);

            let stop = stop_t.lock().unwrap(); //ERR: sistema
            // Poison error on Lock "stop" detected in Thread #2
            if *stop {
                break;
            }

            match report_collector_t.lock() {
                Ok(rep) => rep.produce_report_to_file(PathBuf::from(file_name.clone())),
                Err(_) => {
                    // Poison error on Lock "report_collector" detected in Thread #2
                    todo!()
                },
            };
        }
        println!("Report manager thread terminated");
    }));


    let mut s = String::new();
    println!("Acquisition started, type 'help' to see available commands.");
    loop {
        s.clear();
        stdin().read_line(&mut s).expect("Errore stringa");
        // ERR Acquisition error on main thread

        let (lock, cvar) = &*running_cvar;
        let mut running = lock.lock().unwrap();
        // ERR poison error on lock "running" detected in main thread

        match s.trim().to_lowercase().as_str() {
            "resume" | "r" => {
                *running = true;
                println!("Resumed");
                cvar.notify_all();
            }
            "pause" | "p" => {
                *running = false;
                println!("Paused");
                cvar.notify_all();
            }
            "stop" | "s" => {
                let mut stop = stop.lock().unwrap(); //ERR: sistema
                *stop = true;

                *running = false;
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
            // TODO: spostare le stringhe in costanti a parte
            any => {
                println!("Wrong command: {}", any)
            }
        }
    }

    // TODO: magari si può gestire meglio la terminazione dei thread
    for t in threads {
        t.join().expect("TT"); //ERR: sistema
    }
}

fn command_line_acquisition(
    network_interface: &mut String,
    time_interval: &mut usize,
    file_name: &mut String,
    filter: &mut String,
) -> Result<(), Error> {
    let cli = Args::parse();

    if cli.guided {
        let mut buffer = String::new();
        let devices = list_all_devices();

        // Network interface selection
        println!("Select network interface from the following: ");
        devices
            .iter()
            .filter(|device| device.flags.connection_status == ConnectionStatus::Connected) // da cambiare, non dovrei vedere Device o ConnectionStatus
            .for_each(|device| println!("- {}", device.name));

        if let Err(_) = stdin().read_line(&mut buffer) {
            // Reading error on network interface
            todo!()
        }
        *network_interface = buffer.trim().to_string();

        buffer.clear();

        // Time interval
        println!("Insert time interval between report production: ");
        if let Err(_) = stdin().read_line(&mut buffer) {
            // Reading error on time interval
            todo!()
        }

        if let Ok(val) = buffer.trim().parse() {
            *time_interval = val;
        } else {
            // Parse error on time interval, insert a number
            todo!();
        }

        buffer.clear();

        // File name
        println!("Insert file name for the report: ");
        if let Err(_) = stdin().read_line(&mut buffer) {
            // Reading error on file name
            todo!()
        }
        *file_name = buffer.trim().to_string();

        buffer.clear();

        // FilterW
        println!("Insert packet filter string: ");
        if let Err(_) = stdin().read_line(&mut buffer) {
            // Reading error on filter
            todo!()
        }

        *filter = buffer.trim().to_string();

        return Ok(());
    }

    match cli.network_interface {
        Some(interface) => *network_interface = interface,
        None => {
            *network_interface = match list_all_devices().first() {
                Some(first_device) => {
                    let interface = first_device.name.clone();
                    println!("Interface: {}", interface);
                    interface
                }
                None => return Err(Error::NoDevicesError),
            }
        }
    }

    match cli.time_interval {
        Some(interval) => *time_interval = interval,
        None => {
            *time_interval = {
                println!("Time interval: {}", DEFAULT_TIME_INTERVAL);
                DEFAULT_TIME_INTERVAL
            }
        }
    }

    match cli.file_name {
        Some(name) => *file_name = name,
        None => {
            *file_name = {
                println!("File name: {}", DEFAULT_FILE_NAME);
                DEFAULT_FILE_NAME.to_string()
            }
        }
    }

    match cli.filter_string {
        Some(f) => *filter = f,
        None => {
            *filter = {
                println!("Filter: {}", DEFAULT_FILTER_STRING);
                DEFAULT_FILTER_STRING.to_string()
            }
        }
    }

    Ok(())
}
