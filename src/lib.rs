use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use pcap::{Device, Capture, ConnectionStatus};
use pktparse::{ethernet, ipv4, tcp, udp, icmp, arp};
use std::net::Ipv4Addr;
use std::string::ToString;
use pktparse::ip::IPProtocol;

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

//service function to print the hashmap
pub fn print_hashmap(hm: &HashMap<ConnInfo, ConnData>) -> () {
    let mut i = 1;

    for (key, value) in hm {
        println!("{}|{}:{}", i, key, value);
        i += 1;
    }
}

pub fn start_capture(interface_name: &str, bpf_program: &str) -> () {
    let mut cap = Capture::from_device(interface_name).unwrap()// TODO assume the device exists and we are authorized to open it
        .promisc(true)
       // .snaplen(65535)
        //.buffer_size(65)//serve per vedere subito output quando inviamo pochi dati, altrimenti non vedevo efficacia filtri
        .open().unwrap()
        ;//TODO check error in opening and starting a capture

    println!("Sniffing process in promiscuous mode is active on interface: {}", interface_name);

    let mut report: HashMap<ConnInfo, ConnData> = HashMap::new();

    cap.filter(bpf_program, true).unwrap();
    while let Ok(packet) = cap.next_packet() { //TODO fare controllo sul next packet

        if let Ok((payload_e, frame)) = ethernet::parse_ethernet_frame(packet.data) {
            //println!("{}", payload_e.len());
            match frame.ethertype {
                ethernet::EtherType::IPv4 => {
                    if let Ok((payload_i, datagram)) = ipv4::parse_ipv4_header(payload_e) {
                        match datagram.protocol {
                            IPProtocol::TCP => {
                                if let Ok((_payload_t, segment)) = tcp::parse_tcp_header(payload_i) {
                                    //TODO da wrappare
                                    let ci = ConnInfo::new(datagram.source_addr, datagram.dest_addr, segment.source_port, segment.dest_port, datagram.protocol.tostring(), "".to_string());
                                    let cd = ConnData::new(packet.header.ts, packet.header.ts, payload_e.len() + 38);
                                    report.entry(ci)
                                        .and_modify(|cd| {
                                            cd.total_bytes += payload_e.len() + 38;
                                            cd.ts_last = packet.header.ts
                                        })
                                        .or_insert(cd);
                                    println!("{:?}", segment);
                                    if segment.dest_port == 80 || segment.source_port == 80 { //capire come considerare le porte
                                        //println!("HTTP message.");
                                    } else if segment.dest_port == 443 || segment.source_port == 443 {
                                        //println!("HTTPS message.");
                                    } else if segment.dest_port == 22 || segment.source_port == 22 {
                                        //println!("SSH message.");
                                    }
                                } else {
                                    println!("Error parsing TCP segment.");
                                }
                            }

                            IPProtocol::UDP => {
                                if let Ok((_payload_u, udp_datagram)) = udp::parse_udp_header(payload_i) {
                                    //println!("{:?}", udp_datagram);
                                    //TODO da wrappare in una funzione
                                    let ci = ConnInfo::new(datagram.source_addr, datagram.dest_addr, udp_datagram.source_port, udp_datagram.dest_port, datagram.protocol.tostring(), "".to_string());
                                    let cd = ConnData::new(packet.header.ts, packet.header.ts, payload_e.len() + 38);
                                    report.entry(ci)
                                        .and_modify(|cd| {
                                            cd.total_bytes += payload_e.len() + 38;
                                            cd.ts_last = packet.header.ts
                                        })
                                        .or_insert(cd);
                                    println!("{:?}", udp_datagram);
                                    if udp_datagram.dest_port == 53 || udp_datagram.source_port == 53 {
                                        // println!("DNS message.");
                                    } else if udp_datagram.dest_port == 161 || udp_datagram.source_port == 161 {
                                        //println!("SNMP message.");
                                    }
                                } else {
                                    println!("Error parsing UDP datagram.");
                                }
                            }

                            IPProtocol::ICMP => { //TODO
                                if let Ok((_payload, _packet)) = icmp::parse_icmp_header(payload_i) {
                                    println!("{:?}", _packet);
                                } else {
                                    println!("Error parsing ICMP packet.");
                                }
                            }

                            _ => { println!("L4 protocol not supported") }
                        }
                    } else {
                        println!("Error parsing IP datagram.");
                    }
                }

                //TODO ethernet::EtherType::IPv6 => {}
                ethernet::EtherType::ARP => { //TODO manage for report
                    if let Ok((_payload, _packet)) = arp::parse_arp_pkt(payload_e) {
                        println!("{:x?}", _packet);
                    } else {
                        println!("Error parsing ARP packet.");
                    }
                }
                _ => {
                    println!("L3 protocol not supported");
                }
            }
        } else {
            println!("Error parsing Ethernet frame.");
        }
    }
}

