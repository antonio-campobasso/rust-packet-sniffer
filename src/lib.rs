use pcap::{Device, Capture, Packet, PacketHeader, ConnectionStatus};
use pktparse::{ethernet, ipv4, tcp, udp, ip};
use std::net::Ipv4Addr;

pub struct TupleReport {
    pub ts_first: libc::timeval,
    pub ts_last: libc::timeval,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub bytes: i64,
    //pub descr: String,
}

//TODO implementare tratto display e copy per la struct tupleReport??
//TODO ampliare gamma di protocolli

impl TupleReport {
    pub fn new() -> Self {
        TupleReport {
            ts_first: libc::timeval { tv_sec: 0, tv_usec: 0 },
            ts_last: libc::timeval { tv_sec: 0, tv_usec: 0 },
            src: Ipv4Addr::new(0, 0, 0, 0),
            dst: Ipv4Addr::new(0, 0, 0, 0),
            src_port: 0,
            dst_port: 0,
            protocol: "".to_string(),
            bytes: 0,
            //descr: "".to_string(),
        }
    }
    //TODO Parsing headers and insert filter (decidere ancora dove implementare filter)
}

// Start capture --> default snaplen is 65535 (the maximum length of a packet captured into the buffer).
pub fn start_capture(interface_name: &str) -> () { //esiste la filter e la stats per la struct Capture
    let mut cap = Capture::from_device(interface_name).unwrap()// assume the device exists and we are authorized to open it
        .promisc(true)
        .open().unwrap();// activate the handle // assume activation worked
    //check error in opening and starting a capture
    println!("Sniffing process in promiscuous mode is active on interface: {}", interface_name);

    let mut tr = TupleReport::new();
    while let Ok(packet) = cap.next_packet() { //fare controllo sul next packet
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
                                    println!("{:?}", segment);
                                } else {
                                    println!("Error parsing TCP segment.");
                                }
                            }
                            ip::IPProtocol::UDP => {
                                if let Ok((_payload, udp_datagram)) = udp::parse_udp_header(payload) {
                                    println!("{:?}", udp_datagram);
                                } else {
                                    println!("Error parsing UDP datagram.");
                                }
                            }
                            _ => { println!("L4 protocol not supported") }
                        }
                    } else {
                        println!("Error parsing IP datagram.");
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
        if d.flags.connection_status.eq(&ConnectionStatus::Connected){
            println!("{:?}:{:?} - IP Net interface: {:?}", d.name, d.flags.connection_status, d.addresses[1].addr);
        }else {
            println!("{:?}:{:?}", d.name, d.flags.connection_status);
        }

    }
    devices
}
