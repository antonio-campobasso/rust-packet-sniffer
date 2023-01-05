use libc::{suseconds_t, time_t, timeval};
use pcap::{Active, Capture, ConnectionStatus, Device, Packet, PacketHeader};
use pktparse::arp::Operation;
use pktparse::ethernet::MacAddress;
use pktparse::icmp::{parse_icmp_header, IcmpCode};
use pktparse::ip::IPProtocol;
use pktparse::{arp, ethernet, ipv4, tcp, udp};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::string::ToString;

//--------------------------------------
#[derive(Eq, PartialEq, Hash, Debug)]
/// ConnInfo is the key of our hashmap, this tuple is unique for each connection
pub struct ConnInfo {
    ///source address (IP or MAC)
    pub src: String,
    ///destination address (IP or MAC)
    pub dst: String,
    ///tcp or udp source port
    pub src_port: u16,
    ///tcp or udp destination port
    pub dst_port: u16,
    ///TCP or UDP or ICMP
    pub protocol: String,
    ///it's a brief description of what application level is doing
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
///ConnData is the value field of our hashmap
pub struct ConnData {
    ///ts_first is the timestamp of the first packet sent or received in a connection
    pub ts_first: timeval,
    ///ts_last is the timestamp of the last packet of a connection
    pub ts_last: timeval,
    ///total_bytes is a value representing the cumulative numebr of bytes exchanged in a connection
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
///PacketData is a struct containing the information and data of a packet in a connection
pub struct PacketData {
    ///ci used as a key for recognizing a packet
    pub ci: ConnInfo,
    ///cd used to save data of a packet in a connection
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
        let cd = ConnData::new(packet_header.ts, packet_header.ts, length + 38); //+38 pach_header.len 
        Self { ci, cd }
    }
}

//----------------------------------------
///CaptureDevice struct describes the device used for sniffing
pub struct CaptureDevice {
    ///name of the device (eth0, wlan0...)
    _interface_name: String,
    ///Optionally you may set a filter
    _filter: Option<String>,
    ///cap is the capture context
    cap: Capture<Active>,
}

#[derive(Debug, PartialEq)]
pub enum NetworkInterfaceError {
    CaptureDeviceOpeningError(String),
    WrongNameFormat(String),
    FilterError(String),
    NoDevicesError(String),
}

impl CaptureDevice {
    pub fn new(
        interface_name: String,
        filter: Option<String>,
    ) -> Result<Self, NetworkInterfaceError> {
        let cap_d = Capture::from_device(interface_name.as_str());
        let mut cap_d_string = match cap_d {
            Ok(inner) => {
                let dev = inner
                    .promisc(true)
                    .snaplen(65535)
                    .buffer_size(131072) //serve per vedere subito output quando inviamo pochi dati, altrimenti non vedevo efficacia filtri
                    .open();
                match dev {
                    Ok(inner_dev) => inner_dev,
                    Err(e) => {
                        return Err(NetworkInterfaceError::CaptureDeviceOpeningError(
                            e.to_string(),
                        ));
                    }
                }
            }
            Err(e) => {
                return Err(NetworkInterfaceError::WrongNameFormat(e.to_string()));
            }
        };

        if filter.is_some() {
            let filtered = cap_d_string.filter(&filter.as_ref().unwrap(), true);
            match filtered {
                Ok(_) => {}
                Err(_e) => {
                    return Err(NetworkInterfaceError::FilterError("ERROR: filter not found\n".to_string()));
                }
            }
        }

        Ok(Self {
            _interface_name: interface_name,
            _filter: filter,
            cap: cap_d_string,
        })
    }

    ///It is a synchronous function waiting for next packet from the capture context
    pub fn next_packet(&mut self) -> Result<PacketData, ParsingError> {
        let p = self.cap.next_packet().unwrap();
        let parsed_p = parse(p);
        match parsed_p {
            Ok(packet) => Ok(packet),
            Err(e) => {
                Err(e)
            }
        }
    }
}

//----------------------------------------------------------
/// It is a function listing all devices available for sniffing
pub fn list_all_devices() -> Result<Vec<Device>, NetworkInterfaceError> {
    let dev_list = Device::list();
    match dev_list {
        Ok(devices) => Ok(devices
            .iter()
            .filter(|device| device.flags.connection_status == ConnectionStatus::Connected)
            .cloned()
            .collect()),
        Err(e) => {
            return Err(NetworkInterfaceError::NoDevicesError(e.to_string()));
        }
    }
}
//----------------------------------------------
#[derive(Debug, PartialEq)]
///Containing all the error possible during the creation of the report
pub enum ReportError {
    CreationFileError(String),
    HeaderWritingError(String),
    ReportWritingError(String),
    FooterWritingError(String),
}

///It is a struct wrapping the hashmap, containing the result of the sniffing
pub struct ReportCollector {
    report: HashMap<ConnInfo, ConnData>,
    /// it is the "zero" time
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

    ///it is a function adding the packet in the report data structure
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
                    cd.total_bytes += packet.cd.total_bytes + 38;
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

    /// it used for sorting report based on timeval
    fn sort_report(&self) -> Option<Vec<(&ConnInfo, &ConnData)>> {
        let mut v: Vec<(&ConnInfo, &ConnData)> = self.report.iter().collect();
        v.sort_by(|a, b| {
            if a.1.ts_first.tv_sec == b.1.ts_first.tv_sec {
                a.1.ts_first
                    .tv_usec
                    .partial_cmp(&b.1.ts_first.tv_usec)
                    .unwrap()
            } else {
                a.1.ts_first
                    .tv_sec
                    .partial_cmp(&b.1.ts_first.tv_sec)
                    .unwrap()
            }
        });

        return Some(v);
    }
    /// it's a function to create a file in which inserting the report data structure in a human readable format
    pub fn produce_report_to_file(&self, file_name: PathBuf) -> Result<(), ReportError> {
        let of = File::create(file_name);
        let mut f = match of {
            Ok(file) => file,
            Err(e) => {
                return Err(ReportError::CreationFileError(e.to_string()));
            }
        };
        let header = "\n\t---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n\t\tn\t|\t\t\tsource\t\t|\t\tdestination\t\t|\tprotocol|\t\tts_first\t|\t\tts_last\t\t|\ttotal_bytes |\t\t\t\t\t\t\tdescription\t\t\t\t\t\t\t|\n\t---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n".to_string();
        let footer = "\t---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n";
        let h = f.write_all(header.as_bytes()); // guardare il warning di clion su uso di result ???
        match h {
            Ok(_) => {}
            Err(e) => {
                return Err(ReportError::HeaderWritingError(e.to_string()));
            }
        }
        let mut i = 0;


        for (k, v) in self.sort_report().unwrap() {
            //let s = format!("\t{:>5}\t|\t{:>15}\t|\t{:>15}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}.{:06}\t|\t{:>7}.{:06}\t|\t{:>7}\t|\t{:>7}\t|\n",i,k.src.to_string(),k.dst.to_string(),k.src_port.to_string(),k.dst_port.to_string(),k.protocol.to_string(),(v.ts_first.tv_sec - self.now.tv_sec), (v.ts_first.tv_usec-self.now.tv_usec),(v.ts_last.tv_sec-self.now.tv_sec),(v.ts_last.tv_usec-self.now.tv_usec), v.total_bytes.to_string(),k.app_descr.to_string());
            let ts_first: timeval = ReportCollector::sub_timeval(v.ts_first, self.now);
            let ts_last: timeval = ReportCollector::sub_timeval(v.ts_last, self.now);
            //creare una string con app description e  porte
            //let s = format!("\t{:>5}\t|\t{:>15}\t|\t{:>15}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}\t|\t{:>7}.{:06}\t|\t{:>7}.{:06}\t|\t{:>7}\t|\t{:>7}\t|\n",i,k.src.to_string(),k.dst.to_string(),k.src_port.to_string(),k.dst_port.to_string(),k.protocol.to_string(),(v.ts_first.tv_sec - self.now.tv_sec), v.ts_first.tv_usec,(v.ts_last.tv_sec-self.now.tv_sec),v.ts_last.tv_usec, v.total_bytes.to_string(),k.app_descr.to_string());
            let s = format!("\t{:>5}\t|\t{:>18}\t|\t{:>18}\t|\t{:>7}\t|\t{:>7}.{:06}\t|\t{:>7}.{:06}\t|\t{:>12}| {:<60}\t|\n", i, k.src.to_string(), k.dst.to_string(), k.protocol.to_string(), ts_first.tv_sec, ts_first.tv_usec, ts_last.tv_sec, ts_last.tv_usec, v.total_bytes.to_string(), k.app_descr.to_string());
            f.write_all(s.as_bytes()).unwrap();
            match h {
                Ok(_) => {}
                Err(e) => {
                    return Err(ReportError::ReportWritingError(e.to_string()));
                }
            }
            i += 1;
        }
        let f = f.write_all(footer.as_bytes());
        match f {
            Ok(_) => {}
            Err(e) => {
                return Err(ReportError::FooterWritingError(e.to_string()));
            }
        }
        Ok(())
    }
}

#[derive(Debug,PartialEq)]
pub enum ParsingError {
    NotSupported(String),
    PacketParsingError(String),
}

///it is a function to determine the activity of level 6 over udp
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

///it is a function to determine the activity of level 6 over tcp
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

/// it is the core function of the program, used for parsing the raw data packet and classifying what has been sniffed from the device
fn parse(packet: Packet) -> Result<PacketData, ParsingError> {
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
                                Ok(PacketData::new(
                                    datagram.source_addr.to_string(),
                                    datagram.dest_addr.to_string(),
                                    segment.source_port,
                                    segment.dest_port,
                                    datagram.protocol.tostring(),
                                    packet.header,
                                    payload_e.len(),
                                    s,
                                )) //aggiungere app description
                            } else {
                                return Err(ParsingError::PacketParsingError(
                                    "Error parsing TCP segment.".to_string(),
                                ));
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
                                Ok(PacketData::new(
                                    datagram.source_addr.to_string(),
                                    datagram.dest_addr.to_string(),
                                    udp_datagram.source_port,
                                    udp_datagram.dest_port,
                                    datagram.protocol.tostring(),
                                    packet.header,
                                    payload_e.len(),
                                    s,
                                ))
                            } else {
                                return Err(ParsingError::PacketParsingError(
                                    "Error parsing UDP datagram.".to_string(),
                                ));
                            }
                        }

                        IPProtocol::ICMP => {
                            if let Ok((_payload, icmp_header)) = parse_icmp_header(payload_i) {
                                if icmp_header.code == IcmpCode::EchoRequest {
                                    let s = format!("Echo (ping) request");
                                    Ok(PacketData::new(
                                        datagram.source_addr.to_string(),
                                        datagram.dest_addr.to_string(),
                                        0,
                                        0,
                                        datagram.protocol.tostring(),
                                        packet.header,
                                        payload_e.len(),
                                        s,
                                    ))
                                } else if icmp_header.code == IcmpCode::EchoReply {
                                    let s = format!("Echo (ping) reply");
                                    Ok(PacketData::new(
                                        datagram.source_addr.to_string(),
                                        datagram.dest_addr.to_string(),
                                        0,
                                        0,
                                        datagram.protocol.tostring(),
                                        packet.header,
                                        payload_e.len(),
                                        s,
                                    ))
                                } else {
                                    let s = format!("Destination unreachable");
                                    Ok(PacketData::new(
                                        datagram.source_addr.to_string(),
                                        datagram.dest_addr.to_string(),
                                        0,
                                        0,
                                        datagram.protocol.tostring(),
                                        packet.header,
                                        payload_e.len(),
                                        s,
                                    ))
                                }
                            } else {
                                return Err(ParsingError::PacketParsingError(
                                    "Error parsing ICMP packet.".to_string(),
                                ));
                            }
                        }
                        IPProtocol::ICMP6 => {
                            return Err(ParsingError::NotSupported(
                                "ICMP6 not supported".to_string(),
                            ));
                        }
                        IPProtocol::IGMP => {
                            return Err(ParsingError::NotSupported(
                                "IGMP not supported".to_string(),
                            ));
                        }
                        _ => {
                            return Err(ParsingError::NotSupported(
                                "L4 protocol not supported".to_string(),
                            ));
                        }
                    }
                } else {
                    return Err(ParsingError::PacketParsingError(
                        "Error parsing IPv4 datagram.".to_string(),
                    ));
                }
            }
            ethernet::EtherType::IPv6 => {
                return Err(ParsingError::NotSupported(
                    "IPv6 datagram not supported".to_string(),
                ));
            }

            ethernet::EtherType::ARP => {
                if let Ok((_payload, arp_header)) = arp::parse_arp_pkt(payload_e) {
                    if arp_header.operation == Operation::Request {
                        let s = format!(
                            "Request - Who has {} ? Tell {}",
                            arp_header.dest_addr, arp_header.src_addr
                        );
                        Ok(PacketData::new(
                            frame.source_mac.tostring(),
                            frame.dest_mac.tostring(),
                            0,
                            0,
                            "ARP".to_string(),
                            packet.header,
                            payload_e.len(),
                            s,
                        )) //aggiungere app description
                    } else {
                        let s = format!(
                            "Reply - {} is at {}",
                            arp_header.dest_addr,
                            arp_header.src_mac.tostring()
                        );
                        Ok(PacketData::new(
                            frame.source_mac.tostring(),
                            frame.dest_mac.tostring(),
                            0,
                            0,
                            "ARP".to_string(),
                            packet.header,
                            payload_e.len(),
                            s,
                        )) //aggiungere app description
                    }
                } else {
                    return Err(ParsingError::PacketParsingError(
                        "Error parsing ARP packet.".to_string(),
                    ));
                }
            }
            _ => {
                return Err(ParsingError::NotSupported(
                    "L3 protocol not supported".to_string(),
                ));
            }
        }
    } else {
        return Err(ParsingError::PacketParsingError(
            "Error parsing Ethernet frame.".to_string(),
        ));
    }
}
