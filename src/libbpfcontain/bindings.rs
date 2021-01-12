/* automatically generated by rust-bindgen 0.56.0 */

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct __BindgenBitfieldUnit<Storage, Align> {
    storage: Storage,
    align: [Align; 0],
}
impl<Storage, Align> __BindgenBitfieldUnit<Storage, Align> {
    #[inline]
    pub const fn new(storage: Storage) -> Self {
        Self { storage, align: [] }
    }
}
impl<Storage, Align> __BindgenBitfieldUnit<Storage, Align>
where
    Storage: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    pub fn get_bit(&self, index: usize) -> bool {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = self.storage.as_ref()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        byte & mask == mask
    }
    #[inline]
    pub fn set_bit(&mut self, index: usize, val: bool) {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = &mut self.storage.as_mut()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        if val {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
    #[inline]
    pub fn get(&self, bit_offset: usize, bit_width: u8) -> u64 {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        let mut val = 0;
        for i in 0..(bit_width as usize) {
            if self.get_bit(i + bit_offset) {
                let index = if cfg!(target_endian = "big") {
                    bit_width as usize - 1 - i
                } else {
                    i
                };
                val |= 1 << index;
            }
        }
        val
    }
    #[inline]
    pub fn set(&mut self, bit_offset: usize, bit_width: u8, val: u64) {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        for i in 0..(bit_width as usize) {
            let mask = 1 << i;
            let val_bit_is_set = val & mask == mask;
            let index = if cfg!(target_endian = "big") {
                bit_width as usize - 1 - i
            } else {
                i
            };
            self.set_bit(index + bit_offset, val_bit_is_set);
        }
    }
}
pub const MINOR_WILDCARD: i32 = -1;
pub mod policy_decision_t {
    pub type Type = ::std::os::raw::c_uint;
    pub const BPFCON_NO_DECISION: Type = 0;
    pub const BPFCON_ALLOW: Type = 1;
    pub const BPFCON_DENY: Type = 2;
    pub const BPFCON_TAINT: Type = 4;
}
pub mod file_permission_t {
    pub type Type = ::std::os::raw::c_uint;
    pub const BPFCON_MAY_EXEC: Type = 1;
    pub const BPFCON_MAY_WRITE: Type = 2;
    pub const BPFCON_MAY_READ: Type = 4;
    pub const BPFCON_MAY_APPEND: Type = 8;
    pub const BPFCON_MAY_CREATE: Type = 16;
    pub const BPFCON_MAY_DELETE: Type = 32;
    pub const BPFCON_MAY_RENAME: Type = 64;
    pub const BPFCON_MAY_SETATTR: Type = 128;
    pub const BPFCON_MAY_CHMOD: Type = 256;
    pub const BPFCON_MAY_CHOWN: Type = 512;
    pub const BPFCON_MAY_LINK: Type = 1024;
    pub const BPFCON_MAY_EXEC_MMAP: Type = 2048;
    pub const BPFCON_MAY_CHDIR: Type = 4096;
}
pub mod capability_t {
    pub type Type = ::std::os::raw::c_uint;
    pub const BPFCON_CAP_NET_BIND_SERVICE: Type = 1;
    pub const BPFCON_CAP_NET_RAW: Type = 2;
    pub const BPFCON_CAP_NET_BROADCAST: Type = 4;
    pub const BPFCON_CAP_DAC_OVERRIDE: Type = 8;
    pub const BPFCON_CAP_DAC_READ_SEARCH: Type = 16;
}
pub mod net_category_t {
    pub type Type = ::std::os::raw::c_uint;
    pub const BPFCON_NET_WWW: Type = 1;
    pub const BPFCON_NET_IPC: Type = 2;
}
pub mod net_operation_t {
    pub type Type = ::std::os::raw::c_uint;
    pub const BPFCON_NET_CONNECT: Type = 1;
    pub const BPFCON_NET_BIND: Type = 2;
    pub const BPFCON_NET_ACCEPT: Type = 4;
    pub const BPFCON_NET_LISTEN: Type = 8;
    pub const BPFCON_NET_SEND: Type = 16;
    pub const BPFCON_NET_RECV: Type = 32;
    pub const BPFCON_NET_CREATE: Type = 64;
    pub const BPFCON_NET_SHUTDOWN: Type = 128;
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct event {
    pub unused: ::std::os::raw::c_int,
}
#[test]
fn bindgen_test_layout_event() {
    assert_eq!(
        ::std::mem::size_of::<event>(),
        4usize,
        concat!("Size of: ", stringify!(event))
    );
    assert_eq!(
        ::std::mem::align_of::<event>(),
        4usize,
        concat!("Alignment of ", stringify!(event))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<event>())).unused as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(event),
            "::",
            stringify!(unused)
        )
    );
}
pub type event_t = event;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct bpfcon_container {
    pub default_deny: ::std::os::raw::c_uchar,
    pub default_taint: ::std::os::raw::c_uchar,
}
#[test]
fn bindgen_test_layout_bpfcon_container() {
    assert_eq!(
        ::std::mem::size_of::<bpfcon_container>(),
        2usize,
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
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpfcon_container>())).default_taint as *const _ as usize },
        1usize,
        concat!(
            "Offset of field: ",
            stringify!(bpfcon_container),
            "::",
            stringify!(default_taint)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct bpfcon_process {
    pub container_id: ::std::os::raw::c_ulong,
    pub pid: ::std::os::raw::c_uint,
    pub tgid: ::std::os::raw::c_uint,
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 1usize], u8>,
    pub __bindgen_padding_0: [u8; 7usize],
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
}
impl bpfcon_process {
    #[inline]
    pub fn in_execve(&self) -> ::std::os::raw::c_uchar {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(0usize, 1u8) as u8) }
    }
    #[inline]
    pub fn set_in_execve(&mut self, val: ::std::os::raw::c_uchar) {
        unsafe {
            let val: u8 = ::std::mem::transmute(val);
            self._bitfield_1.set(0usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn tainted(&self) -> ::std::os::raw::c_uchar {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(1usize, 1u8) as u8) }
    }
    #[inline]
    pub fn set_tainted(&mut self, val: ::std::os::raw::c_uchar) {
        unsafe {
            let val: u8 = ::std::mem::transmute(val);
            self._bitfield_1.set(1usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_1(
        in_execve: ::std::os::raw::c_uchar,
        tainted: ::std::os::raw::c_uchar,
    ) -> __BindgenBitfieldUnit<[u8; 1usize], u8> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 1usize], u8> =
            Default::default();
        __bindgen_bitfield_unit.set(0usize, 1u8, {
            let in_execve: u8 = unsafe { ::std::mem::transmute(in_execve) };
            in_execve as u64
        });
        __bindgen_bitfield_unit.set(1usize, 1u8, {
            let tainted: u8 = unsafe { ::std::mem::transmute(tainted) };
            tainted as u64
        });
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct mnt_ns_fs {
    pub mnt_ns: ::std::os::raw::c_uint,
    pub device_id: ::std::os::raw::c_ulong,
}
#[test]
fn bindgen_test_layout_mnt_ns_fs() {
    assert_eq!(
        ::std::mem::size_of::<mnt_ns_fs>(),
        16usize,
        concat!("Size of: ", stringify!(mnt_ns_fs))
    );
    assert_eq!(
        ::std::mem::align_of::<mnt_ns_fs>(),
        8usize,
        concat!("Alignment of ", stringify!(mnt_ns_fs))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<mnt_ns_fs>())).mnt_ns as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(mnt_ns_fs),
            "::",
            stringify!(mnt_ns)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<mnt_ns_fs>())).device_id as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(mnt_ns_fs),
            "::",
            stringify!(device_id)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
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
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
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
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct dev_policy_key {
    pub container_id: ::std::os::raw::c_ulong,
    pub major: ::std::os::raw::c_uint,
    pub minor: ::std::os::raw::c_long,
}
#[test]
fn bindgen_test_layout_dev_policy_key() {
    assert_eq!(
        ::std::mem::size_of::<dev_policy_key>(),
        24usize,
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
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<dev_policy_key>())).minor as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(dev_policy_key),
            "::",
            stringify!(minor)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
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
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct net_policy_key {
    pub container_id: ::std::os::raw::c_ulong,
}
#[test]
fn bindgen_test_layout_net_policy_key() {
    assert_eq!(
        ::std::mem::size_of::<net_policy_key>(),
        8usize,
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
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct ipc_policy_key {
    pub container_id: ::std::os::raw::c_ulong,
    pub other_container_id: ::std::os::raw::c_ulong,
}
#[test]
fn bindgen_test_layout_ipc_policy_key() {
    assert_eq!(
        ::std::mem::size_of::<ipc_policy_key>(),
        16usize,
        concat!("Size of: ", stringify!(ipc_policy_key))
    );
    assert_eq!(
        ::std::mem::align_of::<ipc_policy_key>(),
        8usize,
        concat!("Alignment of ", stringify!(ipc_policy_key))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<ipc_policy_key>())).container_id as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(ipc_policy_key),
            "::",
            stringify!(container_id)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<ipc_policy_key>())).other_container_id as *const _ as usize
        },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(ipc_policy_key),
            "::",
            stringify!(other_container_id)
        )
    );
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
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
