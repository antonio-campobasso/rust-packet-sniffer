use packet_sniffer::*;

use std::{
    collections::HashMap,
    fs::File,
    io::{stdin, Write},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Condvar, Mutex},
    thread::{self, sleep},
    time::Duration,
};

// TODO: introduci possibilità di acquisizione raw? stampa pacchetto per pacchetto

use clap::{Error, Parser};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]

// NOTE: considera se implementare guided mode
struct Args {
    /// Enables guided mode, where the parameter are asked by the program.
    #[clap(short, long, action, value_name = "guided mode")]
    guided: bool,

    /// Network interface to perform the sniffing operation. Defaults to the first interface found.
    #[clap(value_parser, value_name = "network interface")]
    network_interface: Option<String>,

    /// Time interval between report writings. Defaults to 10 seconds.
    #[clap(value_parser, value_name = "time interval")]
    time_interval: Option<u64>,

    /// Name of the file in which the report will be written. Defaults to "report.txt".
    #[clap(value_parser, value_name = "output file")]
    output_file: Option<PathBuf>,

    /// Filter to apply to sniffed packets
    #[clap(short, long, value_parser, value_name = "filter")]
    filter: Option<String>,
}


#[derive(PartialEq)]
enum State {
    RUN,
    PAUSE,
}

const DEFAULT_INTERVAL: u64 = 10;
const DEFAULT_FILE_NAME: &str = "report.txt";

fn main() {
    let cli = Args::parse();

    let network_interface ;
    let time_interval: u64 ;
    let output_file ;
    let filter;

    let mut threads = vec![];

    let report_collector = Arc::new(Mutex::new(ReportCollector::new()));
    let prog_state = Arc::new((Mutex::new(State::RUN), Condvar::new()));
    let stop_flag = Arc::new(Mutex::new(false));
    // NOTE: non posso usare STOP come stato perchè altrimenti si rischia il deadlock

    //list_all_devices()
    // TODO: modalità per inserire i valori uno ad uno. Vale la pena? magari impostare solo valori default senza guided mode?
    match cli.network_interface {
        Some(interface) => network_interface = interface,
        None => network_interface = "en3".to_string(), //qui da cambiare, prendi la lista di dispositivi e prendi il primo
    }

    match cli.time_interval {
        Some(interval) => time_interval = interval,
        None => time_interval = DEFAULT_INTERVAL, // magari definisci in una costante
    }

    match cli.output_file {
        Some(file) => output_file = file,
        None => output_file = PathBuf::from_str(DEFAULT_FILE_NAME).unwrap(), // Da gestire l'errore del file??
    }

    match cli.filter {
        Some(f) => filter = f,
        None => filter = "".to_string(),
    }

    println!(
        "Args: {}, {}, {}",
        network_interface,
        time_interval,
        output_file.to_str().unwrap()
    ); // DEBUG

    let report_collector_t = report_collector.clone();
    let prog_state_t = prog_state.clone();
    let stop_flag_t = stop_flag.clone();

    threads.push(thread::spawn(move || {
        let mut capture = CaptureDevice::new(network_interface, Some(filter));
        while let Ok(packet) = capture.next_packet() {
            //sleep(Duration::from_secs(3)); // DEBUG
            //println!("Pacchetto catturato"); // DEBUG

            let (lock, cvar) = &*prog_state_t;
            let _guard = cvar.wait_while(lock.lock().unwrap(), |state| *state == State::PAUSE);

            let stop = stop_flag_t.lock().unwrap();
            if *stop {
                break;
            }
            println!("Pacchetto Inserito : {:?} - {}", packet.ci, packet.cd); // DEBUG
            let mut rep = report_collector_t.lock().unwrap(); //ERR: sistema
            rep.add_packet(packet); //ERR: sistema
           

        }
        println!("Capture connection terminated.");
    }));

    let report_collector_t = report_collector.clone();
    let prog_state_t = prog_state.clone();
    let stop_flag_t = stop_flag.clone();

    // TODO: considera se la pausa blocca la Creazione di report o no
    threads.push(thread::spawn(move || {
        loop {
            sleep(Duration::from_secs(time_interval));
            // NOTE: può capitare che il comando STOP venga inviato durante lo sleep
            // in questo caso il programma non può terminare finchè non scade il timer, un po' uno spreco
            // TODO: considera di usare un thread che ha solo un timer(loop con sleep)
            // che pilota un flag/condvar. Al posto della sleep qui sopra si potrebbe usare una condvar che controlla
            // se il timer è scaduto oppure se è stato ricevuto il comando STOP

            let (lock, cvar) = &*prog_state_t;

            let _guard = cvar.wait_while(lock.lock().unwrap(), |state| *state == State::PAUSE);

            let stop = stop_flag_t.lock().unwrap(); //ERR: sistema
            if *stop {
                break;
            }

            let rep = report_collector_t.lock().unwrap();
            rep.produce_report_to_file(output_file.clone()); // DEBUG
        }
        println!("Report manager terminated"); //DEBUG
    }));

    let mut s = String::new();
    println!("Acquisition started, type help to see available commands.");
    loop {
        print!("> ");
        s.clear();
        stdin().read_line(&mut s).expect("Errore stringa"); //ERR: sistema
        print!("\n");

        let (lock, cvar) = &*prog_state;
        let mut state = lock.lock().unwrap(); //ERR: sistema

        match s.trim().to_lowercase().as_str() {
            "resume" | "r" => {
                *state = State::RUN;
                println!("Play");
                cvar.notify_all();
            }
            "pause" | "p" => {
                *state = State::PAUSE;
                println!("Pausa");
                cvar.notify_all();
            }
            "stop" | "s" => {
                let mut stop = stop_flag.lock().unwrap();
                *stop = true;

                *state = State::RUN;
                println!("Stop");
                cvar.notify_all();
                break;
            }
            "help" | "h" => {
                println!(
                    "> Pause (p)    => Pauses packet acquisition and report generation.
> Resume (r)    => Resumes packet acquisition and report generation.
> Stop (s)      => Stops the program.
> Help (h)      => Shows line commands. "
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