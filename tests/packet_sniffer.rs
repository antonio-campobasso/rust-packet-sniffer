use libc::timeval;
use packet_sniffer::*;
use pcap::Capture;
use std::path::Path;
use pktparse::ip::IPProtocol;



//--------------------------------------

#[test]
fn conn_info_created_with_valid_values() {
    let conn_info = ConnInfo::new("me".to_string(),"you".to_string(),1,2, "UDP".to_string(),"Some messages".to_string());
    assert_eq!(conn_info.src,"me".to_string());
    assert_eq!(conn_info.dst,"you".to_string());
    assert_eq!(conn_info.src_port,1);
    assert_eq!(conn_info.dst_port,2);
    assert_eq!(conn_info.protocol,"UDP".to_string());
    assert_eq!(conn_info.app_descr,"Some messages".to_string());
}

#[test]
fn conn_info_display_trait() {
    let conn_info = ConnInfo::new("me".to_string(),"you".to_string(),1,2, "UDP".to_string(),"Some messages".to_string());
    assert_eq!(format!("The conn_info is: {conn_info}"), "The conn_info is: (me|you|UDP|1|2|Some messages)");
}

#[test]
#[should_panic]
fn conn_info_display_trait_err() {
    let conn_info = ConnInfo::new("me".to_string(),"you".to_string(),1,2, "UDP".to_string(),"Some messages".to_string());
    assert_eq!(format!("The conn_info is: {conn_info}"), "The conn_info is: (m|you|UDP|1|2|Some messages)");
}

#[test]
#[should_panic]
fn conn_info_created_with_invalid_src() {
    let conn_info = ConnInfo::new("me".to_string(),"you".to_string(),1,2, "UDP".to_string(),"Some messages".to_string());
    assert_eq!(conn_info.src,"wrong".to_string());
    assert_eq!(conn_info.dst,"you".to_string());
    assert_eq!(conn_info.src_port,1);
    assert_eq!(conn_info.dst_port,2);
    assert_eq!(conn_info.protocol,"UDP".to_string());
    assert_eq!(conn_info.app_descr,"Some messages".to_string());
}

#[test]
#[should_panic]
fn conn_info_created_with_invalid_src_port() {
    let conn_info = ConnInfo::new("me".to_string(),"you".to_string(),1,2, "UDP".to_string(),"Some messages".to_string());
    assert_eq!(conn_info.src,"me".to_string());
    assert_eq!(conn_info.dst,"you".to_string());
    assert_eq!(conn_info.src_port,12);
    assert_eq!(conn_info.dst_port,2);
    assert_eq!(conn_info.protocol,"UDP".to_string());
    assert_eq!(conn_info.app_descr,"Some messages".to_string());
}

#[test]
#[should_panic]
fn conn_info_created_with_invalid_dst() {
    let conn_info = ConnInfo::new("me".to_string(),"you".to_string(),1,2, "UDP".to_string(),"Some messages".to_string());
    assert_eq!(conn_info.src,"me".to_string());
    assert_eq!(conn_info.dst,"wrong".to_string());
    assert_eq!(conn_info.src_port,1);
    assert_eq!(conn_info.dst_port,2);
    assert_eq!(conn_info.protocol,"UDP".to_string());
    assert_eq!(conn_info.app_descr,"Some messages".to_string());
}

#[test]
#[should_panic]
fn conn_info_created_with_invalid_dst_port() {
    let conn_info = ConnInfo::new("me".to_string(),"you".to_string(),1,2, "UDP".to_string(),"Some messages".to_string());
    assert_eq!(conn_info.src,"me".to_string());
    assert_eq!(conn_info.dst,"you".to_string());
    assert_eq!(conn_info.src_port,1);
    assert_eq!(conn_info.dst_port,21);
    assert_eq!(conn_info.protocol,"UDP".to_string());
    assert_eq!(conn_info.app_descr,"Some messages".to_string());
}

//--------------------------------------

#[test]
fn conn_data_created_with_valid_values() {
    let conn_data = ConnData::new(timeval { tv_sec: (1), tv_usec: (0) },timeval { tv_sec: (2), tv_usec: (1) },10);
    assert_eq!(conn_data.ts_first.tv_sec as u64, 1);
    assert_eq!(conn_data.ts_first.tv_usec as u64, 0);
    assert_eq!(conn_data.ts_last.tv_sec as u64, 2);
    assert_eq!(conn_data.ts_last.tv_usec as u64, 1);
    assert_eq!(conn_data.total_bytes, 10);
}

#[test]
fn conn_data_display_trait() {
    let conn_data = ConnData::new(timeval { tv_sec: (1), tv_usec: (0) },timeval { tv_sec: (2), tv_usec: (1) },10);
    assert_eq!(format!("The conn_data is: {conn_data}"), "The conn_data is: (tot_bytes:10 ts_first:1.000000 ts_last:2.000001)");
}

#[test]
#[should_panic]
fn conn_data_created_with_invalid_values() {
    let conn_data = ConnData::new(timeval { tv_sec: (1), tv_usec: (0) },timeval { tv_sec: (2), tv_usec: (1) },10);
    assert_eq!(conn_data.ts_first.tv_sec as u64, 1);
    assert_eq!(conn_data.ts_first.tv_usec as u64, 0);
    assert_eq!(conn_data.ts_last.tv_sec as u64, 2);
    assert_eq!(conn_data.ts_last.tv_usec as u64, 1);
    assert_eq!(conn_data.total_bytes, 11);
}

//--------------------------------------


#[test]
fn implementation_to_string_trait() {
   let ip1 = IPProtocol::ICMP;
   let ip2 = IPProtocol::UDP;
   let ip3 = IPProtocol::TCP;
   //let x: MacAddress = MacAddress::;
   assert_eq!(ip1.tostring(),"ICMP".to_string());
   assert_eq!(ip2.tostring(),"UDP".to_string());
   assert_eq!(ip3.tostring(),"TCP".to_string());
}

#[test]
#[should_panic]
fn implementation_to_string_trait_err() {
   let ip1 = IPProtocol::ICMP;
   let ip2 = IPProtocol::UDP;
   let ip3 = IPProtocol::TCP;

   assert_eq!(ip1.tostring(),"ICP".to_string());
   assert_eq!(ip2.tostring(),"UDP".to_string());
   assert_eq!(ip3.tostring(),"TCP".to_string());
}

//--------------------------------------

#[test]
fn packet_data_created_with_valid_values() {
    let mut cap = Capture::from_file(Path::new("tests/data/packet_snaplen_20.pcap")).unwrap();
    let pack_head = cap.next_packet().unwrap().header;
    let packet_data = PacketData::new("8.8.8.8".to_string(), "1.1.1.1".to_string(), 12, 40, "UDP".to_string(), pack_head , 12, "Some messages".to_string());
    assert_eq!(packet_data.cd.ts_first.tv_sec as u64, pack_head.ts.tv_sec as u64);
    assert_eq!(packet_data.cd.ts_first.tv_usec as u64, pack_head.ts.tv_usec as u64);
    assert_eq!(packet_data.cd.ts_last.tv_sec as u64, pack_head.ts.tv_sec as u64);
    assert_eq!(packet_data.cd.ts_last.tv_usec as u64, pack_head.ts.tv_usec as u64);
    assert_eq!(packet_data.cd.total_bytes,pack_head.len as usize - 48 ); //TODO togliere il -48
    assert_eq!(packet_data.ci.dst, "1.1.1.1".to_string());
    assert_eq!(packet_data.ci.app_descr, "Some messages".to_string());
    assert_eq!(packet_data.ci.dst_port, 40);
    assert_eq!(packet_data.ci.src, "8.8.8.8".to_string());
    assert_eq!(packet_data.ci.src_port, 12);
} 

//--------------------------------------

#[test]
fn capture_device_created_with_valid_values() {
    let interface_name = "eth0".into();
    let cap_d = CaptureDevice::new(interface_name, None);
    assert!(cap_d.is_ok());
}

#[test]
fn capture_device_created_with_inesistent_interface() {
    let interface_name = "eth777".into();
    let cap_d = CaptureDevice::new(interface_name, None);
    assert_eq!(cap_d.err().unwrap(), NetworkInterfaceError::CaptureDeviceOpeningError("libpcap error: SIOCGIFHWADDR: No such device".to_string()));
}

#[test]
fn capture_device_created_with_valid_filter() {
    let interface_name = "eth0".into();
    let cap_d = CaptureDevice::new(interface_name, Some("igmp".to_string()));
    assert!(cap_d.is_ok());
}

#[test]
fn  capture_device_created_with_inesistent_filter() {
    let interface_name = "eth0".into();
    let cap_d = CaptureDevice::new(interface_name, Some("wrong_filter".to_string()));
    assert_eq!(cap_d.err().unwrap(), NetworkInterfaceError::FilterError("ERROR: filter not found\n".to_string())); //non riesco a confrontare stringa
}

/* 
#[test]
#[ignore]
fn next_packet_parsing_error() {
    let interface_name = "eth0".into();
    let cap_d = CaptureDevice::new(interface_name, Some("ip6".to_string()));
    assert_eq!(cap_d.unwrap().next_packet().err().unwrap(),ParsingError::PacketParsingError("Error parsing TCP segment.".to_string()));
}
*/

#[test]
fn network_devices_listed() {
    let devs = list_all_devices();
    assert!(devs.is_ok());
}


//--------------------------------------

#[test]
fn report_produced_with_success() {
    let mut rep = ReportCollector::new();
    let mut cap = Capture::from_file(Path::new("tests/data/packet_snaplen_20.pcap")).unwrap();
    let pack_head = cap.next_packet().unwrap().header;
    let packet_data = PacketData::new("8.8.8.8".to_string(), "1.1.1.1".to_string(), 12, 40, "UDP".to_string(), pack_head , 12, "Some messages".to_string());
    rep.add_packet(packet_data);
    assert!(rep.produce_report_to_file("rep.txt".into()).is_ok()); //eliminare rep.txt che si crea durante esecuzione dei test
}

#[test]
fn report_produced_with_error() {
    let mut rep = ReportCollector::new();
    let mut cap = Capture::from_file(Path::new("tests/data/packet_snaplen_20.pcap")).unwrap();
    let pack_head = cap.next_packet().unwrap().header;
    let packet_data = PacketData::new("8.8.8.8".to_string(), "1.1.1.1".to_string(), 12, 40, "UDP".to_string(), pack_head , 12, "Some messages".to_string());
    rep.add_packet(packet_data);
    assert_eq!(rep.produce_report_to_file("/home/str/rrr/uvx".into()).err().unwrap(), ReportError::CreationFileError("No such file or directory (os error 2)".to_string()));
}







