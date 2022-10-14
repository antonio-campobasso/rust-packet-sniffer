use libc::{sleep, suseconds_t, time, time_t, timeval};
use pcap::{Active, Capture, ConnectionStatus, Device, Error, Packet, PacketHeader};
use pktparse::arp::Operation;
use pktparse::ethernet::MacAddress;
use pktparse::icmp::{parse_icmp_header, IcmpCode};
use pktparse::ip::IPProtocol;
use pktparse::ipv4::IPv4Header;
use pktparse::{arp, ethernet, icmp, ipv4, tcp, udp};
use std::collections::HashMap;
use std::fmt::{format, Display, Formatter};
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::string::{self, ToString};

//--------------------------------------
#[derive(Eq, PartialEq, Hash, Debug)]
pub struct ConnInfo {
    pub src: String,
    ///source address (IP or MAC)
    pub dst: String,
    ///destination address (IP or MAC)
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub app_descr: String,
}

impl ConnInfo {
    pub fn new(
        src: String,
        dst: String,
        src_port: u16,
        dst_port: u16,
        protocol: String,
        app_descr: String,
    ) -> Self {
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
        write!(
            f,
            "({}|{}|{}|{}|{}|{})",
            self.src, self.dst, self.protocol, self.src_port, self.dst_port, self.app_descr
        )
    }
}

//---------------------------
pub struct ConnData {
    pub ts_first: timeval,
    pub ts_last: timeval,
    pub total_bytes: usize,
}

impl ConnData {
    pub fn new(ts_first: timeval, ts_last: timeval, total_bytes: usize) -> Self {
        ConnData {
            ts_first,
            ts_last,
            total_bytes,
        }
    }
}

impl Display for ConnData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(tot_bytes:{} ts_first:{}.{:06} ts_last:{}.{:06})",
            self.total_bytes,
            self.ts_first.tv_sec,
            self.ts_first.tv_usec,
            self.ts_last.tv_sec,
            self.ts_last.tv_usec
        )
    }
}

//-------------------------------------
pub trait ToStr {
    fn tostring(&self) -> String;
}

impl ToStr for IPProtocol {
    fn tostring(&self) -> String {
        match self {
            IPProtocol::ICMP => "ICMP".to_string(),
            IPProtocol::UDP => "UDP".to_string(),
            IPProtocol::TCP => "TCP".to_string(),
            _ => "".to_string(),
        }
    }
}

impl ToStr for MacAddress {
    fn tostring(&self) -> String {
        /*let s = String::from(self.0[0].to_string()+ ":" + &*self.0[1].to_string() + ":" + &*self.0[2].to_string() +":" + &*self.0[3].to_string() + ":"+ &*self.0[4].to_string() +":"+ &*self.0[5].to_string());
        return s;*/
        let s = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        );
        s
    }
}

//--------------------------------------
pub struct PacketData {
    pub ci: ConnInfo,
    pub cd: ConnData,
}

impl PacketData {
    pub fn new(
        src_addr: String,
        dest_addr: String,
        src: u16,
        dst: u16,
        protocol: String,
        packet_header: &PacketHeader,
        length: usize,
        description: String,
    ) -> Self {
        let ci = ConnInfo::new(
            src_addr,
            dest_addr,
            src,
            dst,
            protocol,
            description.to_string(),
        );
        let cd = ConnData::new(packet_header.ts, packet_header.ts, length + 38); //+38
        Self { ci, cd }
    }
}

//----------------------------------------
pub struct CaptureDevice {
    interface_name: String,
    filter: Option<String>,
    cap: Capture<Active>,
}

impl CaptureDevice {
    pub fn new(interface_name: String, filter: Option<String>) -> Self {
        let mut cap = Capture::from_device(interface_name.as_str())
            .unwrap() // TODO assume the device exists and we are authorized to open it
            .promisc(true)
            //.snaplen(65535)
            .buffer_size(1600) //serve per vedere subito output quando inviamo pochi dati, altrimenti non vedevo efficacia filtri
            .open()
            .unwrap(); //TODO check error in opening and starting a capture

        //println!("Sniffing process in promiscuous mode is active on interface: {}", interface_name);
        cap.filter(&filter.as_ref().unwrap(), true).unwrap();
        Self {
            interface_name,
            filter,
            cap,
        }
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
    now: timeval,
}

impl ReportCollector {
    pub fn new() -> Self {
        ReportCollector {
            report: HashMap::new(),
            now: timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        }
    }

    pub fn add_packet(&mut self, packet: PacketData) -> () {
        if self.report.is_empty() {
            self.now = packet.cd.ts_first;
        }
        if packet.ci.protocol.eq("ARP") {
            self.report.insert(packet.ci, packet.cd);
        } else {
            self.report
                .entry(packet.ci)
                .and_modify(|cd| {
                    cd.total_bytes += packet.cd.total_bytes + 38; //+38?
                    cd.ts_last = packet.cd.ts_first
                })
                .or_insert(packet.cd);
        }
    }

    fn sub_timeval(sot: timeval, min: timeval) -> timeval {
        let tf1 = (sot.tv_sec * 1000000) as u64;
        let tf2 = sot.tv_usec as u64;
        let tf = tf1 + tf2;

        let tl1 = (min.tv_sec * 1000000) as u64;
        let tl2 = min.tv_usec as u64;
        let tl = tl1 + tl2;
        let time = tf - tl;

        let int = time / 1000000;
        let dec = time % 1000000;

        timeval {
            tv_sec: int as time_t,
            tv_usec: dec as suseconds_t,
        }
    }

    pub fn produce_report_to_file(&self, file_name: PathBuf) -> () {
        let mut f = File::create(file_name).unwrap();
        let header = "\n\t---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n\t\tn\t|\t\t\tsource\t\t|\t\tdestination\t\t|\tprotocol|\t\tts_first\t|\t\tts_last\t\t|\ttotal_bytes |\t\t\t\t\t\t\tdescription\t\t\t\t\t\t\t|\n\t---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n".to_string();
        let footer = "\t---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n";
        f.write_all(header.as_bytes()); // guardare il warning di clion su uso di result
        let mut i = 0;

        for (k, v) in self.report.iter() {
            //let s = format!("\t{:>5}\t|\t{:>15}\t|\t{:>15}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}.{:06}\t|\t{:>7}.{:06}\t|\t{:>7}\t|\t{:>7}\t|\n",i,k.src.to_string(),k.dst.to_string(),k.src_port.to_string(),k.dst_port.to_string(),k.protocol.to_string(),(v.ts_first.tv_sec - self.now.tv_sec), (v.ts_first.tv_usec-self.now.tv_usec),(v.ts_last.tv_sec-self.now.tv_sec),(v.ts_last.tv_usec-self.now.tv_usec), v.total_bytes.to_string(),k.app_descr.to_string());
            let ts_first: timeval = ReportCollector::sub_timeval(v.ts_first, self.now);
            let ts_last: timeval = ReportCollector::sub_timeval(v.ts_last, self.now);
            //creare una string con app description e  porte
            //let s = format!("\t{:>5}\t|\t{:>15}\t|\t{:>15}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}.{:06}\t|\t{:>7}.{:06}\t|\t{:>7}\t|\t{:>7}\t|\n",i,k.src.to_string(),k.dst.to_string(),k.src_port.to_string(),k.dst_port.to_string(),k.protocol.to_string(),(v.ts_first.tv_sec - self.now.tv_sec), v.ts_first.tv_usec,(v.ts_last.tv_sec-self.now.tv_sec),v.ts_last.tv_usec, v.total_bytes.to_string(),k.app_descr.to_string());
            let s = format!("\t{:>5}\t|\t{:>18}\t|\t{:>18}\t|\t{:>7}\t|\t{:>7}.{:06}\t|\t{:>7}.{:06}\t|\t{:>12}| {:<60}\t|\n", i, k.src.to_string(), k.dst.to_string(), k.protocol.to_string(), ts_first.tv_sec, ts_first.tv_usec, ts_last.tv_sec, ts_last.tv_usec, v.total_bytes.to_string(), k.app_descr.to_string());
            f.write_all(s.as_bytes());
            i += 1;
        }
        f.write_all(footer.as_bytes()); //guardare warning su uso di REsult
    }
}
//----------------------------------------------------------
// list devices
pub fn list_all_devices() -> Vec<Device> {
    let devices = Device::list().unwrap();

    /*     for d in &devices {
        if d.flags.connection_status.eq(&ConnectionStatus::Connected) && d.addresses.len() > 1 {
            println!("{:?}: {:?} - IP Net interface: {:?}", d.name, d.flags.connection_status, d.addresses[1].addr);
        } else if d.flags.connection_status.eq(&ConnectionStatus::Connected) && d.addresses.len() < 2 {
            continue; //Per il Mac bypass llw0 and awdl interface because not chooseable
        } else {
            println!("{:?}: {:?}", d.name, d.flags.connection_status);
        }
    } */
    //devices.iter().filter(|device| device.flags.connection_status == ConnectionStatus::Connected).collect::<Vec<Device>>()
    devices
}


///
fn app_recognition_udp(src: u16, dst: u16) -> String {
    if dst == 53 {
        return "DNS standard query.".to_string();
    } else if src == 53 {
        return "DNS response.".to_string();
    } else if dst == 161 || src == 161 {
        return "SNMP connection".to_string();
    } else if dst == 1900 || src == 1900 {
        return "SSDP connection".to_string();
    } else if dst == 443 || src == 443 {
        return "Transmission encrypted over UDP".to_string();
    }
    "app not recognized".to_string()
}

///
fn app_recognition_tcp(src: u16, dst: u16) -> String {
    if dst == 80 || src == 80 {
        return "HTTP connection.".to_string();
    } else if dst == 443 || src == 443 {
        return "HTTP over TLS connection".to_string();
    } else if dst == 22 || src == 22 {
        return "SSH connection".to_string();
    }
    "app not recognized".to_string()
}

fn parse(packet: Packet) -> PacketData {
    // TODO errori
    if let Ok((payload_e, frame)) = ethernet::parse_ethernet_frame(packet.data) {
        match frame.ethertype {
            ethernet::EtherType::IPv4 => {
                if let Ok((payload_i, datagram)) = ipv4::parse_ipv4_header(payload_e) {
                    match datagram.protocol {
                        IPProtocol::TCP => {
                            if let Ok((_payload_t, segment)) = tcp::parse_tcp_header(payload_i) {
                                let s = format!(
                                    "{} -> {} {}",
                                    segment.source_port,
                                    segment.dest_port,
                                    app_recognition_tcp(segment.source_port, segment.dest_port)
                                );
                                PacketData::new(
                                    datagram.source_addr.to_string(),
                                    datagram.dest_addr.to_string(),
                                    segment.source_port,
                                    segment.dest_port,
                                    datagram.protocol.tostring(),
                                    packet.header,
                                    payload_e.len(),
                                    s,
                                ) //aggiungere app description
                            } else {
                                panic!("Error parsing TCP segment.");
                            }
                        }
                        IPProtocol::UDP => {
                            if let Ok((_payload_u, udp_datagram)) = udp::parse_udp_header(payload_i)
                            {
                                let s = format!(
                                    "{} -> {} {}",
                                    udp_datagram.source_port,
                                    udp_datagram.dest_port,
                                    app_recognition_udp(
                                        udp_datagram.source_port,
                                        udp_datagram.dest_port
                                    )
                                );
                                PacketData::new(
                                    datagram.source_addr.to_string(),
                                    datagram.dest_addr.to_string(),
                                    udp_datagram.source_port,
                                    udp_datagram.dest_port,
                                    datagram.protocol.tostring(),
                                    packet.header,
                                    payload_e.len(),
                                    s,
                                )
                            } else {
                                panic!("Error parsing UDP datagram.");
                            }
                        }

                        IPProtocol::ICMP => {
                            if let Ok((_payload, icmp_header)) = parse_icmp_header(payload_i) {
                                if icmp_header.code == IcmpCode::EchoRequest {
                                    let s = format!("Echo (ping) request");
                                    PacketData::new(
                                        datagram.source_addr.to_string(),
                                        datagram.dest_addr.to_string(),
                                        0,
                                        0,
                                        datagram.protocol.tostring(),
                                        packet.header,
                                        payload_e.len(),
                                        s,
                                    )
                                } else if icmp_header.code == IcmpCode::EchoReply {
                                    let s = format!("Echo (ping) reply");
                                    PacketData::new(
                                        datagram.source_addr.to_string(),
                                        datagram.dest_addr.to_string(),
                                        0,
                                        0,
                                        datagram.protocol.tostring(),
                                        packet.header,
                                        payload_e.len(),
                                        s,
                                    )
                                } else {
                                    let s = format!("Destination unreachable");
                                    PacketData::new(
                                        datagram.source_addr.to_string(),
                                        datagram.dest_addr.to_string(),
                                        0,
                                        0,
                                        datagram.protocol.tostring(),
                                        packet.header,
                                        payload_e.len(),
                                        s,
                                    )
                                }
                            } else {
                                panic!("Error parsing ICMP packet.");
                            }
                        }
                        IPProtocol::ICMP6 => {
                            panic!("ICMP6 not supported");
                        }
                        IPProtocol::IGMP => {
                            panic!("IGMP not supported");
                        }
                        _ => {
                            panic!("L4 protocol not supported")
                        }
                    }
                } else {
                    panic!("Error parsing IPv4 datagram.");
                }
            }
            ethernet::EtherType::IPv6 => {
                panic!(" IPv6 datagram not supported");
            }

            ethernet::EtherType::ARP => {
                if let Ok((_payload, arp_header)) = arp::parse_arp_pkt(payload_e) {
                    if arp_header.operation == Operation::Request {
                        let s = format!(
                            "Request - Who has {} ? Tell {}",
                            arp_header.dest_addr, arp_header.src_addr
                        );
                        PacketData::new(
                            frame.source_mac.tostring(),
                            frame.dest_mac.tostring(),
                            0,
                            0,
                            "ARP".to_string(),
                            packet.header,
                            payload_e.len(),
                            s,
                        ) //aggiungere app description
                    } else {
                        let s = format!(
                            "Reply - {} is at {}",
                            arp_header.dest_addr,
                            arp_header.src_mac.tostring()
                        );
                        PacketData::new(
                            frame.source_mac.tostring(),
                            frame.dest_mac.tostring(),
                            0,
                            0,
                            "ARP".to_string(),
                            packet.header,
                            payload_e.len(),
                            s,
                        ) //aggiungere app description
                    }
                } else {
                    panic!("Error parsing ARP packet.")
                }
            }
            _ => {
                panic!("L3 protocol not supported")
            }
        }
    } else {
        panic!("Error parsing Ethernet frame.");
    }
}
