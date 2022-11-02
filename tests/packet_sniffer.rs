use libc::timeval;
use packet_sniffer::*;

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
fn conn_data_created_with_valid_values() {
    let conn_data = ConnData::new(timeval { tv_sec: (1), tv_usec: (0) },timeval { tv_sec: (2), tv_usec: (1) },10);
    assert_eq!(conn_data.ts_first.tv_sec as u64, 1);
    assert_eq!(conn_data.ts_first.tv_usec as u64, 0);
    assert_eq!(conn_data.ts_last.tv_sec as u64, 2);
    assert_eq!(conn_data.ts_last.tv_usec as u64, 1);
    assert_eq!(conn_data.total_bytes, 10);
}


/* 
#[test]
fn packet_data_created_with_valid_values() {
    let packet_data = PacketData::new("8.8.8.8".to_string(), "1.1.1.1".to_string(), "me".to_string(), "you".to_string(), "UDP".to_string(), &(timeval { tv_sec: (2), tv_usec: (1)}, {12}, {12}).into() , 12, "Some messages".to_string());
    let conn_info = ConnInfo::new("me".to_string(),"you".to_string(),1,2, "UDP".to_string(),"Some messages".to_string());
    let conn_data = ConnData::new(timeval { tv_sec: (1), tv_usec: (0) },timeval { tv_sec: (2), tv_usec: (1) },10);

}*/

/*
#[test]
#[should_panic]
fn capture_device_created_with_valid_values() {
    let cap_d = CaptureDevice::new("eth0".to_string(), None).unwrap_err().kind();
let expected_error_kind = NetworkInterfaceError:: CaptureDeviceOpeningError;
assert!(cap_d.
}, expected_error_kind);
}
*/

