use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Write;
use pcap::{Device, Capture, ConnectionStatus, Packet, PacketHeader, Active, Error};
use pktparse::{ethernet, ipv4, tcp, udp, icmp, arp};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::string::{ToString, self};
use libc::{sleep, suseconds_t, time, time_t, timeval};
use pktparse::ip::IPProtocol;
use pktparse::ipv4::IPv4Header;


//--------------------------------------
#[derive(Eq, PartialEq, Hash, Debug)]
pub struct ConnInfo {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub app_descr: String,
}

impl ConnInfo {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, protocol: String, app_descr: String) -> Self {
        ConnInfo {
            src,
            dst,
            src_port,
            dst_port,
            protocol,
            app_descr,
        }
    }
}

impl Display for ConnInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}|{}|{}|{}|{}|{})", self.src, self.dst, self.protocol, self.src_port, self.dst_port, self.app_descr)
    }
}

//---------------------------
pub struct ConnData {
    pub ts_first: libc::timeval,
    pub ts_last: libc::timeval,
    pub total_bytes: usize,

}

impl ConnData {
    pub fn new(ts_first: libc::timeval, ts_last: libc::timeval, total_bytes: usize) -> Self {
        ConnData {
            ts_first,
            ts_last,
            total_bytes,
        }
    }
}

impl Display for ConnData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "(tot_bytes:{} ts_first:{}.{:06} ts_last:{}.{:06})", self.total_bytes, self.ts_first.tv_sec, self.ts_first.tv_usec, self.ts_last.tv_sec, self.ts_last.tv_usec)
    }
}

//-------------------------------------
pub trait ToStr {
    fn tostring(&self) -> String;
}

impl ToStr for IPProtocol {
    fn tostring(&self) -> String {
        match self {
            IPProtocol::ICMP => { "ICMP".to_string() }
            IPProtocol::UDP => { "UDP".to_string() }
            IPProtocol::TCP => { "TCP".to_string() }
            _ => { "".to_string() }
        }
    }
}

//--------------------------------------
pub struct PacketData {
    pub ci: ConnInfo,
    pub cd: ConnData,
}

impl PacketData {
    pub fn new(datagram: IPv4Header, src: u16, dst: u16, packet_header: &PacketHeader, length: usize) -> Self {
        let ci = ConnInfo::new(datagram.source_addr, datagram.dest_addr, src, dst, datagram.protocol.tostring(), "".to_string());
        let cd = ConnData::new(packet_header.ts, packet_header.ts, length + 38);
        Self { ci, cd }
    }
}

//----------------------------------------
pub struct CaptureDevice {
    interface_name: String,
    filter: Option<String>,
    cap: Capture<Active>
}

impl CaptureDevice {
    pub fn new(interface_name: String, filter: Option<String>) -> Self {
        let mut cap = Capture::from_device(interface_name.as_str()).unwrap()// TODO assume the device exists and we are authorized to open it
            .promisc(true)
            //.snaplen(65535)
            .buffer_size(65)//serve per vedere subito output quando inviamo pochi dati, altrimenti non vedevo efficacia filtri
            .open().unwrap();//TODO check error in opening and starting a capture

        println!("Sniffing process in promiscuous mode is active on interface: {}", interface_name);
        cap.filter(&filter.as_ref().unwrap(), true).unwrap();
        Self { interface_name, filter, cap }
    }

    pub fn next_packet(&mut self) -> Result<PacketData, Error> {
        let p = self.cap.next_packet().unwrap();
        let parsed_p = parse(p);
        Ok(parsed_p)
    }
}

//----------------------------------------------
// TODO: Implementare il tratto drop?

pub struct ReportCollector {
    report: HashMap<ConnInfo, ConnData>,
    now: libc::timeval
}


impl ReportCollector {
    pub fn new() -> Self {
        ReportCollector {
            report: HashMap::new(),
            now: libc::timeval { tv_sec: 0, tv_usec: 0 }
        }
    }

    pub fn add_packet(&mut self, packet: PacketData) -> () {
        if self.report.is_empty(){
            self.now = packet.cd.ts_first;
        }

        self.report.entry(packet.ci)
            .and_modify(|cd| {
                cd.total_bytes += packet.cd.total_bytes + 38;
                cd.ts_last = packet.cd.ts_first
            })
            .or_insert(packet.cd);
    }

    /*pub fn produce_report(&self) -> String {
        //println!("Report in stampa");
        //sleep(Duration::from_secs(2));
        //println!("Report Stampato");
        "res".to_string;
    }*/

    fn sub_timeval(sot: timeval, min: timeval) -> timeval{
        let tf1 = (sot.tv_sec * 1000000) as u64;
        let tf2= sot.tv_usec as u64;
        let tf = tf1+tf2;

        let tl1 = (min.tv_sec * 1000000) as u64;
        let tl2 = min.tv_usec as u64;
        let tl = tl1 +tl2;
        let time= tf-tl;

        let int = time/1000000;
        let dec = time % 1000000;

        timeval {tv_sec: int as time_t, tv_usec: dec as suseconds_t }
    }

    pub fn produce_report_to_file(&self, file_name: PathBuf) -> () {

        let mut f = File::create(file_name).unwrap();
        let header = "\n\t------------------------------------------------------------------------------------\nn\t|\tsource_ip\t|\tdestination_ip\t|\tsrc_port\t|\tdst_port\t|\tprotocol\t|\ttotal_bytes\t|\tdescription\t|\n\t------------------------------------------------------------------------------------\n".to_string();
        let footer = "\t------------------------------------------------------------------------------------\n";
        f.write_all(header.as_bytes());
        let mut i = 0;

        for (k, v) in self.report.iter() {
            //let s = format!("\t{:>5}\t|\t{:>15}\t|\t{:>15}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}.{:06}\t|\t{:>7}.{:06}\t|\t{:>7}\t|\t{:>7}\t|\n",i,k.src.to_string(),k.dst.to_string(),k.src_port.to_string(),k.dst_port.to_string(),k.protocol.to_string(),(v.ts_first.tv_sec - self.now.tv_sec), (v.ts_first.tv_usec-self.now.tv_usec),(v.ts_last.tv_sec-self.now.tv_sec),(v.ts_last.tv_usec-self.now.tv_usec), v.total_bytes.to_string(),k.app_descr.to_string());
            let ts_first: libc::timeval = ReportCollector::sub_timeval(v.ts_first,self.now);
            let ts_last: libc::timeval = ReportCollector::sub_timeval(v.ts_last,self.now);
            //let s = format!("\t{:>5}\t|\t{:>15}\t|\t{:>15}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}.{:06}\t|\t{:>7}.{:06}\t|\t{:>7}\t|\t{:>7}\t|\n",i,k.src.to_string(),k.dst.to_string(),k.src_port.to_string(),k.dst_port.to_string(),k.protocol.to_string(),(v.ts_first.tv_sec - self.now.tv_sec), v.ts_first.tv_usec,(v.ts_last.tv_sec-self.now.tv_sec),v.ts_last.tv_usec, v.total_bytes.to_string(),k.app_descr.to_string());
            let s = format!("\t{:>5}\t|\t{:>15}\t|\t{:>15}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}.{:06}\t|\t{:>7}.{:06}\t|\t{:>7}\t|\t{:>7}\t|\n",i,k.src.to_string(),k.dst.to_string(),k.src_port.to_string(),k.dst_port.to_string(),k.protocol.to_string(),ts_first.tv_sec, ts_first.tv_usec,ts_last.tv_sec,ts_last.tv_usec, v.total_bytes.to_string(),k.app_descr.to_string());
            f.write_all(s.as_bytes());
            i+=1;
        }
        f.write_all(footer.as_bytes());
        //let s = self.report.iter().map(|(k,v)|{k.src.to_string() + k.dst.to_string() + k.src_port.to_string() + k.dst_port.to_string() + k.protocol.to_string() + k.app_descr.to_string() + v.ts_first.to_string() + v.ts_last.to_string() + v.total_bytes.to_string()}).for_each(|x|{f.write_all((header + x).as_byte())});
    }
}

//----------------------------------------------------------
// list devices
pub fn list_all_devices() -> Vec<Device> {
    let devices = Device::list().unwrap();

    for d in &devices {
        if d.flags.connection_status.eq(&ConnectionStatus::Connected) && d.addresses.len() > 1 {
            println!("{:?}: {:?} - IP Net interface: {:?}", d.name, d.flags.connection_status, d.addresses[1].addr);
        } else if d.flags.connection_status.eq(&ConnectionStatus::Connected) && d.addresses.len() < 2 {
            continue; //Per il Mac bypass llw0 and awdl interface because not chooseable
        } else {
            println!("{:?}: {:?}", d.name, d.flags.connection_status);
        }
    }
    devices
}

fn app_recognition_udp(src: u16, dst: u16) -> () {
    if dst == 53 || src == 53 {
        // println!("DNS message.");
    } else if dst == 161 || src == 161 {
        //println!("SNMP message.");
    }
}

fn app_recognition_tcp(src: u16, dst: u16) -> () {
    if dst == 80 || src == 80 {
        //println!("HTTP message.");
    } else if dst == 443 || src == 443 {
        //println!("HTTPS message.");
    } else if dst == 22 || src == 22 {
        //println!("SSH message.");
    }
}

fn parse(packet: Packet) -> PacketData { // TODO errori e app recognition
    if let Ok((payload_e, frame)) = ethernet::parse_ethernet_frame(packet.data) {
        //println!("{}", payload_e.len()); verifica di bytes effettivi trasmessi --> controllo payload del frame e aggiungo 38 (heaeder eth)
        match frame.ethertype {
            ethernet::EtherType::IPv4 => {
                if let Ok((payload_i, datagram)) = ipv4::parse_ipv4_header(payload_e) {
                    match datagram.protocol {
                        IPProtocol::TCP => {
                            if let Ok((_payload_t, segment)) = tcp::parse_tcp_header(payload_i) {
                                //reporting diventa add_packet, anziché passare tutti questi dati, creiamo una struct e la passiamo
                                //reporting(report, datagram, segment.source_port, segment.dest_port, packet.header, payload_e.len());
                                app_recognition_tcp(segment.source_port, segment.dest_port);
                                PacketData::new(datagram,segment.source_port,segment.dest_port,packet.header,payload_e.len())
                                //println!("{:?}", segment);
                            } else {
                                //println!("Error parsing TCP segment.");
                                panic!();
                            }
                        }
                        IPProtocol::UDP => {
                            if let Ok((_payload_u, udp_datagram)) = udp::parse_udp_header(payload_i) {
                                //reporting(report, datagram, udp_datagram.source_port, udp_datagram.dest_port, packet.header, payload_e.len());
                                app_recognition_udp(udp_datagram.source_port, udp_datagram.dest_port);
                                PacketData::new(datagram,udp_datagram.source_port,udp_datagram.dest_port,packet.header,payload_e.len())
                                //println!("{:?}", udp_datagram);
                            } else {
                                //println!("Error parsing UDP datagram.");
                                panic!();
                            }
                        }

                        /*IPProtocol::ICMP => { //TODO
                            if let Ok((_payload, _packet)) = icmp::parse_icmp_header(payload_i) {
                                // println!("{:?}", _packet);
                            } else {
                                println!("Error parsing ICMP packet.");
                            }
                        }*/
                        _ => { panic!()}
                        //println!("L4 protocol not supported") }
                    }
                } else {
                    //println!("Error parsing IP datagram.");
                    panic!();
                }
            }
            //TODO ethernet::EtherType::IPv6 => {
            // }
            /*
            ethernet::EtherType::ARP => { //TODO da capire se inserire o meno nel report
                if let Ok((_payload, _packet)) = arp::parse_arp_pkt(payload_e) {
                    //println!("{:x?}", _packet);
                    //print_hashmap(report);
                } else {
                    println!("Error parsing ARP packet.");
                }
            }*/
            _ => {
                //println!("L3 protocol not supported");
                panic!()
            }
        }
    } else {
        //println!("Error parsing Ethernet frame.");
        panic!();
    }
}

/*
pub struct ConnData {
    pub ts_first_sec: i64,
    pub ts_first_usec: i64,
    pub ts_last_sec: i64,
    pub ts_last_usec: i64,
    pub total_bytes: usize,

}

impl ConnData {
    pub fn new(ts_first: libc::timeval, ts_last: libc::timeval, total_bytes: usize) -> Self {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();


        ConnData {
            ts_first_sec : (now.as_secs() as i64 - ts_first.tv_sec ),
            ts_last_sec : (now.as_secs() as i64 - ts_last.tv_sec  ),
            ts_first_usec : ts_first.tv_usec  ,
            ts_last_usec : ts_last.tv_usec ,
            totalbytes,
        }
    }
}

impl Display for ConnData {
    fn fmt(&self, f: &mut Formatter<'>) -> std::fmt::Result {
        write!(f, "(tot_bytes:{} ts_first:{}.{:06} ts_last:{}.{:06})", self.total_bytes, self.ts_first_sec, self.ts_first_usec, self.ts_last_sec, self.ts_last_usec)
    }
}

//------------

pub fn add_packet(&mut self, packet: PacketData) -> () {
        self.report.entry(packet.ci)
            .and_modify(|cd| {
                cd.total_bytes += packet.cd.total_bytes + 38;
                cd.ts_last_sec = packet.cd.ts_first_sec;
                cd.ts_last_usec = packet.cd.ts_first_usec
            })
            .or_insert(packet.cd);
    }

    /*pub fn produce_report(&self) -> String {
        //println!("Report in stampa");
        //sleep(Duration::from_secs(2));
        //println!("Report Stampato");
        "res".to_string;
    }*/


    pub fn produce_report_to_file(&self, file_name: PathBuf) -> () {

        let mut f = File::create(file_name).unwrap();
        let header = "\n\t---------------------------------------------------------------------------------------------\nn\t|\tsorce\t|\tdest \t|\tsrc_p\t|\tdst_p\t|\tprot \t|\t ts_first \t|\t ts_last  \t|\ttot_b\t|\tdescr\n\t---------------------------------------------------------------------------------------------\n".to_string();
        let footer = "\t---------------------------------------------------------------------------------------------\n";
        f.write_all(header.as_bytes());
        let mut i = 0;

        for (k, v) in self.report.iter() {
            let s = format!("\t{:>5}\t|\t{:>15}\t|\t{:>15}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}.{:06}\t|\t{:>7}.{:06}\t|\t{:>7}\t|\t{:>7}\t|\n",i,k.src.to_string(),k.dst.to_string(),k.src_port.to_string(),k.dst_port.to_string(),k.protocol.to_string(),v.ts_first_sec, v.ts_first_usec,v.ts_last_sec,v.ts_last_usec, v.total_bytes.to_string(),k.app_descr.to_string());
            f.write_all(s.as_bytes());
            i+=1;
            }
        f.write_all(footer.as_bytes());
        //let s = self.report.iter().map(|(k,v)|{k.src.to_string() + k.dst.to_string() + k.src_port.to_string() + k.dst_port.to_string() + k.protocol.to_string() + k.app_descr.to_string() + v.ts_first.to_string() + v.ts_last.to_string() + v.total_bytes.to_string()}).for_each(|x|{f.write_all((header + x).as_byte())});
    }
}
*/

