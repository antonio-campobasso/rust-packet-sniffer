use std::collections::HashMap;
use pcap::{Device, Capture, Packet, PacketHeader, ConnectionStatus};
use pktparse::{ethernet, ipv4, tcp, udp, ip, icmp, arp};
use std::net::Ipv4Addr;

#[derive(Eq, PartialEq, Hash)]
pub struct ConnInfo{
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
            src, //Ipv4Addr::new(0, 0, 0, 0),
            dst, //Ipv4Addr::new(0, 0, 0, 0),
            src_port,  // 1, 2, 5, 6, TCP 18bytes
            dst_port,  // 2, 1, 6, 5 TCP 138 bytes
            protocol,
            app_descr,
        }
    }
}

pub struct ConnData { //ConnData and //ConnInfo
    pub ts_first: libc::timeval,
    pub ts_last: libc::timeval,
    pub total_bytes: u64,

}

//TODO implementare tratto display e copy per la struct tupleReport??
//ampliare gamma di protocolli, anche a livello applicazione guardando alle porte (per DNS è la 53)

impl ConnData {
    pub fn new(ts_first: libc::timeval, ts_last: libc::timeval, total_bytes: u64) -> Self {
        ConnData {
            ts_first, //libc::timeval { tv_sec: 0, tv_usec: 0 },
            ts_last,//libc::timeval { tv_sec: 0, tv_usec: 0 },
            total_bytes,
        }
    }
    //Parsing headers and TODO insert filter (decidere ancora dove implementare filter)
}

// Start capture --> default snaplen is 65535 (the maximum length of a packet captured into the buffer).
pub fn start_capture(interface_name: &str) -> () { //esiste la filter e la stats per la struct Capture
    let mut cap = Capture::from_device(interface_name).unwrap()// assume the device exists and we are authorized to open it
        .promisc(true)
        .open().unwrap();// activate the handle // assume activation worked
    //TODO check error in opening and starting a capture
    println!("Sniffing process in promiscuous mode is active on interface: {}", interface_name);

    // TODO magari creare una HashMap per le varie tuple da inserire poi nel report
    let report: HashMap<ConnInfo, ConnData> = HashMap::new();
    while let Ok(packet) = cap.next_packet() { //TODO fare controllo sul next packet
        //let packet = cap.next_packet().unwrap();
        //println!("{:?}", packet);
        if let Ok((payload, frame)) = ethernet::parse_ethernet_frame(packet.data) {
            println!("{:x?}", frame);
            match frame.ethertype {
                ethernet::EtherType::IPv4 => {
                    if let Ok((payload, datagram)) = ipv4::parse_ipv4_header(payload) {
                        println!("{:?}", datagram);
                        //tr.src = datagram.source_addr;
                        match datagram.protocol {
                            ip::IPProtocol::TCP => {
                                if let Ok((_payload, segment)) = tcp::parse_tcp_header(payload) {
                                    //println!("{:?}", segment);
                                    //verificare se il TupleReport con la seguente tupla (src,dst,p_src,p_dest) è già presente nella hashmap, se sì, incremento il numero di bytes, con il valore total length dell'haeder ip
                                    //se no aggiungerlo alla HashMap. quaando aggiungo, scrivo il ts_first e quando aggiorno, aggiorno anche il ts_end
                                    //let mut tr = TupleReport::new(packet.header.ts, packet.header.ts, datagram.source_addr, datagram.dest_addr, segment.source_port, segment.dest_port, "TCP".to_string(), datagram.length as u64, "".to_string()); //viene distrutta ad ogni iterazione del ciclo

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
                            ip::IPProtocol::UDP => {
                                if let Ok((_payload, udp_datagram)) = udp::parse_udp_header(payload) {
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
                            ip::IPProtocol::ICMP => { //TODO
                                if let Ok((_payload, packet)) = icmp::parse_icmp_header(payload) {
                                    println!("{:?}", packet);
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
                ethernet::EtherType::ARP => { //TODO
                    if let Ok((_payload, packet)) = arp::parse_arp_pkt(payload) {
                        println!("{:x?}", packet);
                    } else {
                        println!("Error parsing ARP packet.");
                    }
                }
                _ => { println!("L3 protocol not supported") }
            }
        } else {
            println!("Error parsing Ethernet frame.");
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
            continue; //bypass llw0 and awdl interface because not chooseable
        } else {
            println!("{:?}: {:?}", d.name, d.flags.connection_status);
        }
    }
    devices
}
