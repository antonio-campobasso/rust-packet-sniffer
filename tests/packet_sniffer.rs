use libc::timeval;
use packet_sniffer::*;
use pcap::{Active, Capture, ConnectionStatus, Device, Packet, PacketHeader};
use std::path::Path;

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
#[should_panic]
#[ignore]
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
#[ignore]
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
#[ignore]
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
#[ignore]
fn conn_info_created_with_invalid_dst_port() {
    let conn_info = ConnInfo::new("me".to_string(),"you".to_string(),1,2, "UDP".to_string(),"Some messages".to_string());
    assert_eq!(conn_info.src,"me".to_string());
    assert_eq!(conn_info.dst,"you".to_string());
    assert_eq!(conn_info.src_port,1);
    assert_eq!(conn_info.dst_port,21);
    assert_eq!(conn_info.protocol,"UDP".to_string());
    assert_eq!(conn_info.app_descr,"Some messages".to_string());
}


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
fn packet_data_created_with_valid_values() {

    let mut cap = Capture::from_file(Path::new("tests/packet_snaplen_20.pcap")).unwrap();
    let pack_head = cap.next_packet().unwrap().header;
    let packet_data = PacketData::new("8.8.8.8".to_string(), "1.1.1.1".to_string(), 12, 40, "UDP".to_string(), pack_head , 12, "Some messages".to_string());
    //assert_eq!(packet_data.cd.ts_first, pack_head.ts.tv_sec);
    //assert_eq!(packet_data.cd.ts_last, pack_head.ts);
    assert_eq!(packet_data.cd.total_bytes,pack_head.len as usize - 48 ); //TODO togliere il -48
    assert_eq!(packet_data.ci.dst, "1.1.1.1".to_string());
    assert_eq!(packet_data.ci.app_descr, "Some messages".to_string());
    assert_eq!(packet_data.ci.dst_port, 40);
    assert_eq!(packet_data.ci.src, "8.8.8.8".to_string());
    assert_eq!(packet_data.ci.src_port, 12);
} 


/*#[test]
#[should_panic]
fn capture_device_created_with_invalid_interface_name() {
    let cap_d = CaptureDevice::new("eth0".to_string(), None).unwrap();
}
 */

#[test]
fn capture_device_created_with_valid_values() {
    let interface_name = "eth0".into();
    let cap_d = CaptureDevice::new(interface_name, None);
    assert!(cap_d.is_ok());
}

#[test]
fn capture_device_created_with_invalid_values() {
    let interface_name = "eth777".into();
    let cap_d = CaptureDevice::new(interface_name, None);
    assert_eq!(cap_d.err(), Some(NetworkInterfaceError::CaptureDeviceOpeningError("libpcap error: SIOCGIFHWADDR: No such device".to_string())));
}


/* 
#[test]
#[should_panic]
fn capture_device_created_with_invalid_interface_name() {
    let cap_d = CaptureDevice::new("eth222".to_string(), None).unwrap();
}
*/


