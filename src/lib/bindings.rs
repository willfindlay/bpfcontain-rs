/* automatically generated by rust-bindgen 0.56.0 */

pub const policy_decision_t_BPFCON_NO_DECISION: policy_decision_t = 0;
pub const policy_decision_t_BPFCON_ALLOW: policy_decision_t = 1;
pub const policy_decision_t_BPFCON_DENY: policy_decision_t = 2;
pub type policy_decision_t = ::std::os::raw::c_uint;
pub const file_permission_t_BPFCON_MAY_EXEC: file_permission_t = 1;
pub const file_permission_t_BPFCON_MAY_WRITE: file_permission_t = 2;
pub const file_permission_t_BPFCON_MAY_READ: file_permission_t = 4;
pub const file_permission_t_BPFCON_MAY_APPEND: file_permission_t = 8;
pub const file_permission_t_BPFCON_MAY_CREATE: file_permission_t = 16;
pub const file_permission_t_BPFCON_MAY_DELETE: file_permission_t = 32;
pub const file_permission_t_BPFCON_MAY_RENAME: file_permission_t = 64;
pub const file_permission_t_BPFCON_MAY_SETATTR: file_permission_t = 128;
pub const file_permission_t_BPFCON_MAY_CHMOD: file_permission_t = 256;
pub const file_permission_t_BPFCON_MAY_CHOWN: file_permission_t = 512;
pub const file_permission_t_BPFCON_MAY_LINK: file_permission_t = 1024;
pub const file_permission_t_BPFCON_MAY_EXEC_MMAP: file_permission_t = 2048;
pub const file_permission_t_BPFCON_MAY_CHDIR: file_permission_t = 4096;
pub type file_permission_t = ::std::os::raw::c_uint;
pub const capability_t_BPFCON_CAP_NET_BIND_SERVICE: capability_t = 1;
pub const capability_t_BPFCON_CAP_NET_RAW: capability_t = 2;
pub const capability_t_BPFCON_CAP_NET_BROADCAST: capability_t = 4;
pub const capability_t_BPFCON_CAP_DAC_OVERRIDE: capability_t = 8;
pub const capability_t_BPFCON_CAP_DAC_READ_SEARCH: capability_t = 16;
pub type capability_t = ::std::os::raw::c_uint;
pub const net_category_t_BPFCON_NET_WWW: net_category_t = 1;
pub const net_category_t_BPFCON_NET_IPC: net_category_t = 2;
pub type net_category_t = ::std::os::raw::c_uint;
pub const net_operation_t_BPFCON_NET_CONNECT: net_operation_t = 1;
pub const net_operation_t_BPFCON_NET_BIND: net_operation_t = 2;
pub const net_operation_t_BPFCON_NET_ACCEPT: net_operation_t = 4;
pub const net_operation_t_BPFCON_NET_LISTEN: net_operation_t = 8;
pub const net_operation_t_BPFCON_NET_SEND: net_operation_t = 16;
pub const net_operation_t_BPFCON_NET_RECV: net_operation_t = 32;
pub const net_operation_t_BPFCON_NET_CREATE: net_operation_t = 64;
pub const net_operation_t_BPFCON_NET_SHUTDOWN: net_operation_t = 128;
pub type net_operation_t = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct bpfcon_container {
    pub default_deny: ::std::os::raw::c_uchar,
}
#[test]
fn bindgen_test_layout_bpfcon_container() {
    assert_eq!(
        ::std::mem::size_of::<bpfcon_container>(),
        1usize,
        concat!("Size of: ", stringify!(bpfcon_container))
    );
    assert_eq!(
        ::std::mem::align_of::<bpfcon_container>(),
        1usize,
        concat!("Alignment of ", stringify!(bpfcon_container))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpfcon_container>())).default_deny as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpfcon_container),
            "::",
            stringify!(default_deny)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct bpfcon_process {
    pub container_id: ::std::os::raw::c_ulong,
    pub pid: ::std::os::raw::c_uint,
    pub tgid: ::std::os::raw::c_uint,
    pub in_execve: ::std::os::raw::c_uchar,
}
#[test]
fn bindgen_test_layout_bpfcon_process() {
    assert_eq!(
        ::std::mem::size_of::<bpfcon_process>(),
        24usize,
        concat!("Size of: ", stringify!(bpfcon_process))
    );
    assert_eq!(
        ::std::mem::align_of::<bpfcon_process>(),
        8usize,
        concat!("Alignment of ", stringify!(bpfcon_process))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpfcon_process>())).container_id as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpfcon_process),
            "::",
            stringify!(container_id)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpfcon_process>())).pid as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpfcon_process),
            "::",
            stringify!(pid)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpfcon_process>())).tgid as *const _ as usize },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(bpfcon_process),
            "::",
            stringify!(tgid)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpfcon_process>())).in_execve as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(bpfcon_process),
            "::",
            stringify!(in_execve)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct fs_policy_key {
    pub container_id: ::std::os::raw::c_ulong,
    pub device_id: ::std::os::raw::c_uint,
}
#[test]
fn bindgen_test_layout_fs_policy_key() {
    assert_eq!(
        ::std::mem::size_of::<fs_policy_key>(),
        16usize,
        concat!("Size of: ", stringify!(fs_policy_key))
    );
    assert_eq!(
        ::std::mem::align_of::<fs_policy_key>(),
        8usize,
        concat!("Alignment of ", stringify!(fs_policy_key))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<fs_policy_key>())).container_id as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(fs_policy_key),
            "::",
            stringify!(container_id)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<fs_policy_key>())).device_id as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(fs_policy_key),
            "::",
            stringify!(device_id)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct file_policy_key {
    pub container_id: ::std::os::raw::c_ulong,
    pub inode_id: ::std::os::raw::c_ulong,
    pub device_id: ::std::os::raw::c_uint,
}
#[test]
fn bindgen_test_layout_file_policy_key() {
    assert_eq!(
        ::std::mem::size_of::<file_policy_key>(),
        24usize,
        concat!("Size of: ", stringify!(file_policy_key))
    );
    assert_eq!(
        ::std::mem::align_of::<file_policy_key>(),
        8usize,
        concat!("Alignment of ", stringify!(file_policy_key))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<file_policy_key>())).container_id as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(file_policy_key),
            "::",
            stringify!(container_id)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<file_policy_key>())).inode_id as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(file_policy_key),
            "::",
            stringify!(inode_id)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<file_policy_key>())).device_id as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(file_policy_key),
            "::",
            stringify!(device_id)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct dev_policy_key {
    pub container_id: ::std::os::raw::c_ulong,
    pub major: ::std::os::raw::c_uint,
}
#[test]
fn bindgen_test_layout_dev_policy_key() {
    assert_eq!(
        ::std::mem::size_of::<dev_policy_key>(),
        16usize,
        concat!("Size of: ", stringify!(dev_policy_key))
    );
    assert_eq!(
        ::std::mem::align_of::<dev_policy_key>(),
        8usize,
        concat!("Alignment of ", stringify!(dev_policy_key))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<dev_policy_key>())).container_id as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(dev_policy_key),
            "::",
            stringify!(container_id)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<dev_policy_key>())).major as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(dev_policy_key),
            "::",
            stringify!(major)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct cap_policy_key {
    pub container_id: ::std::os::raw::c_ulong,
}
#[test]
fn bindgen_test_layout_cap_policy_key() {
    assert_eq!(
        ::std::mem::size_of::<cap_policy_key>(),
        8usize,
        concat!("Size of: ", stringify!(cap_policy_key))
    );
    assert_eq!(
        ::std::mem::align_of::<cap_policy_key>(),
        8usize,
        concat!("Alignment of ", stringify!(cap_policy_key))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<cap_policy_key>())).container_id as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(cap_policy_key),
            "::",
            stringify!(container_id)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct net_policy_key {
    pub container_id: ::std::os::raw::c_ulong,
    pub category: ::std::os::raw::c_uchar,
}
#[test]
fn bindgen_test_layout_net_policy_key() {
    assert_eq!(
        ::std::mem::size_of::<net_policy_key>(),
        16usize,
        concat!("Size of: ", stringify!(net_policy_key))
    );
    assert_eq!(
        ::std::mem::align_of::<net_policy_key>(),
        8usize,
        concat!("Alignment of ", stringify!(net_policy_key))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<net_policy_key>())).container_id as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(net_policy_key),
            "::",
            stringify!(container_id)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<net_policy_key>())).category as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(net_policy_key),
            "::",
            stringify!(category)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct inode_key {
    pub inode_id: ::std::os::raw::c_ulong,
    pub device_id: ::std::os::raw::c_uint,
}
#[test]
fn bindgen_test_layout_inode_key() {
    assert_eq!(
        ::std::mem::size_of::<inode_key>(),
        16usize,
        concat!("Size of: ", stringify!(inode_key))
    );
    assert_eq!(
        ::std::mem::align_of::<inode_key>(),
        8usize,
        concat!("Alignment of ", stringify!(inode_key))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<inode_key>())).inode_id as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(inode_key),
            "::",
            stringify!(inode_id)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<inode_key>())).device_id as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(inode_key),
            "::",
            stringify!(device_id)
        )
    );
}
extern "C" {
    pub fn containerize(container_id: ::std::os::raw::c_ulong) -> ::std::os::raw::c_int;
}
