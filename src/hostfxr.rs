use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::ptr;

use libloading::Library;

use crate::Icd11Error;

type HostfxrHandle = *mut c_void;

#[repr(C)]
struct HostfxrInitializeParameters {
    size: usize,
    host_path: *const c_char,
    dotnet_root: *const c_char,
}

#[repr(i32)]
#[allow(dead_code)]
enum HostfxrDelegateType {
    ComActivation = 0,
    LoadInMemoryAssembly = 1,
    WinrtActivation = 2,
    ComRegister = 3,
    ComUnregister = 4,
    LoadAssemblyAndGetFunctionPointer = 5,
    GetFunctionPointer = 6,
}

type HostfxrInitForCmdLineFn = unsafe extern "C" fn(
    argc: c_int,
    argv: *const *const c_char,
    parameters: *const HostfxrInitializeParameters,
    host_context_handle: *mut HostfxrHandle,
) -> i32;

type HostfxrGetRuntimeDelegateFn = unsafe extern "C" fn(
    host_context_handle: HostfxrHandle,
    delegate_type: HostfxrDelegateType,
    delegate: *mut *mut c_void,
) -> i32;

type HostfxrCloseFn = unsafe extern "C" fn(host_context_handle: HostfxrHandle) -> i32;

type LoadAssemblyAndGetFunctionPointerFn = unsafe extern "C" fn(
    assembly_path: *const c_char,
    type_name: *const c_char,
    method_name: *const c_char,
    delegate_type_name: *const c_char,
    reserved: *const c_void,
    delegate: *mut *mut c_void,
) -> i32;

type BridgeInitFn = unsafe extern "C" fn(
    bundle_dir_utf8: *const c_char,
    data_dir_utf8: *const c_char,
    bind_url_utf8: *const c_char,
    out_port: *mut c_int,
) -> *mut c_char;

type BridgeRequestFn = unsafe extern "C" fn(
    method_utf8: *const c_char,
    path_and_query_utf8: *const c_char,
    body_utf8: *const c_char,
    content_type_utf8: *const c_char,
    out_status: *mut c_int,
) -> *mut c_char;

type BridgeDorisFn = unsafe extern "C" fn(
    release_utf8: *const c_char,
    cert_json_utf8: *const c_char,
    out_status: *mut c_int,
) -> *mut c_char;

type BridgeCodEditFn = unsafe extern "C" fn(
    release_utf8: *const c_char,
    cert_json_utf8: *const c_char,
    out_status: *mut c_int,
) -> *mut c_char;

type BridgeShutdownFn = unsafe extern "C" fn() -> c_int;
type BridgeFreeFn = unsafe extern "C" fn(ptr: *mut c_char);

const UNMANAGED_CALLERS_ONLY_METHOD: *const c_char = usize::MAX as *const c_char;

pub struct DotnetBridgeHost {
    _library: Library,
    init_fn: BridgeInitFn,
    request_fn: BridgeRequestFn,
    doris_fn: BridgeDorisFn,
    codedit_fn: BridgeCodEditFn,
    shutdown_fn: BridgeShutdownFn,
    free_fn: BridgeFreeFn,
    bound_port: u16,
}

// Safety: All managed bridge entry points are thread-safe static methods backed by
// thread-safe ASP.NET Core / SocketsHttpHandler / DorisRuleEngine singletons.
unsafe impl Send for DotnetBridgeHost {}
unsafe impl Sync for DotnetBridgeHost {}

impl DotnetBridgeHost {
    pub fn initialize(
        dotnet_root: &Path,
        hostfxr_path: &Path,
        bundle_dir: &Path,
        data_dir: &Path,
        bind_url: &str,
    ) -> Result<Self, Icd11Error> {
        let icd_api_dll = bundle_dir.join("ICD-API.dll");
        let bridge_dll = bundle_dir.join("DigitvaIcd11Bridge.dll");
        if !icd_api_dll.exists() {
            return Err(Icd11Error::BundleNotFound(format!(
                "Missing ICD-API.dll at {}",
                icd_api_dll.display()
            )));
        }
        if !bridge_dll.exists() {
            return Err(Icd11Error::BundleNotFound(format!(
                "Missing DigitvaIcd11Bridge.dll at {}",
                bridge_dll.display()
            )));
        }

        unsafe {
            let library = Library::new(hostfxr_path).map_err(|e| {
                Icd11Error::DotnetHostError(format!(
                    "Failed to load hostfxr library at {}: {e}",
                    hostfxr_path.display()
                ))
            })?;

            let init_for_cmd: HostfxrInitForCmdLineFn = *library
                .get(b"hostfxr_initialize_for_dotnet_command_line\0")
                .map_err(|e| Icd11Error::DotnetHostError(format!("Missing hostfxr init symbol: {e}")))?;
            let get_delegate: HostfxrGetRuntimeDelegateFn = *library
                .get(b"hostfxr_get_runtime_delegate\0")
                .map_err(|e| Icd11Error::DotnetHostError(format!("Missing hostfxr delegate symbol: {e}")))?;
            let close_fn: HostfxrCloseFn = *library
                .get(b"hostfxr_close\0")
                .map_err(|e| Icd11Error::DotnetHostError(format!("Missing hostfxr close symbol: {e}")))?;

            let icd_api_c = path_to_cstring(&icd_api_dll)?;
            let dotnet_root_c = path_to_cstring(dotnet_root)?;
            let argv = [icd_api_c.as_ptr()];
            let params = HostfxrInitializeParameters {
                size: std::mem::size_of::<HostfxrInitializeParameters>(),
                host_path: icd_api_c.as_ptr(),
                dotnet_root: dotnet_root_c.as_ptr(),
            };

            let mut cxt: HostfxrHandle = ptr::null_mut();
            let rc = init_for_cmd(1, argv.as_ptr(), &params, &mut cxt);
            if rc < 0 || cxt.is_null() {
                return Err(Icd11Error::DotnetHostError(format!(
                    "hostfxr_initialize_for_dotnet_command_line failed with status 0x{rc:08x}"
                )));
            }

            let mut load_fn_ptr: *mut c_void = ptr::null_mut();
            let rc_del = get_delegate(
                cxt,
                HostfxrDelegateType::LoadAssemblyAndGetFunctionPointer,
                &mut load_fn_ptr,
            );
            let _ = close_fn(cxt);
            if rc_del < 0 || load_fn_ptr.is_null() {
                return Err(Icd11Error::DotnetHostError(format!(
                    "hostfxr_get_runtime_delegate failed with status 0x{rc_del:08x}"
                )));
            }

            let load_fn: LoadAssemblyAndGetFunctionPointerFn = std::mem::transmute(load_fn_ptr);
            let bridge_dll_c = path_to_cstring(&bridge_dll)?;
            let type_name_c = CString::new("DigitvaIcd11.Bridge, DigitvaIcd11Bridge").unwrap();

            let init_fn: BridgeInitFn = std::mem::transmute(resolve_method(
                load_fn,
                &bridge_dll_c,
                &type_name_c,
                "Init",
            )?);
            let request_fn: BridgeRequestFn = std::mem::transmute(resolve_method(
                load_fn,
                &bridge_dll_c,
                &type_name_c,
                "Request",
            )?);
            let doris_fn: BridgeDorisFn = std::mem::transmute(resolve_method(
                load_fn,
                &bridge_dll_c,
                &type_name_c,
                "Doris",
            )?);
            let codedit_fn: BridgeCodEditFn = std::mem::transmute(resolve_method(
                load_fn,
                &bridge_dll_c,
                &type_name_c,
                "CodEdit",
            )?);
            let shutdown_fn: BridgeShutdownFn = std::mem::transmute(resolve_method(
                load_fn,
                &bridge_dll_c,
                &type_name_c,
                "Shutdown",
            )?);
            let free_fn: BridgeFreeFn = std::mem::transmute(resolve_method(
                load_fn,
                &bridge_dll_c,
                &type_name_c,
                "Free",
            )?);

            let bundle_c = path_to_cstring(bundle_dir)?;
            let data_c = path_to_cstring(data_dir)?;
            let bind_c = CString::new(bind_url)
                .map_err(|e| Icd11Error::DotnetHostError(format!("Invalid bind_url: {e}")))?;
            let mut port: c_int = 0;

            let err_ptr = init_fn(
                bundle_c.as_ptr(),
                data_c.as_ptr(),
                bind_c.as_ptr(),
                &mut port,
            );
            if !err_ptr.is_null() {
                let err_msg = take_string(err_ptr, free_fn);
                return Err(Icd11Error::DotnetHostError(format!(
                    "DigitvaIcd11Bridge.Init failed: {err_msg}"
                )));
            }

            Ok(Self {
                _library: library,
                init_fn,
                request_fn,
                doris_fn,
                codedit_fn,
                shutdown_fn,
                free_fn,
                bound_port: port as u16,
            })
        }
    }

    pub fn bound_port(&self) -> u16 {
        self.bound_port
    }

    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.bound_port)
    }

    pub fn request(
        &self,
        method: &str,
        path_and_query: &str,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<(u16, String), Icd11Error> {
        let method_c = CString::new(method)
            .map_err(|e| Icd11Error::DotnetHostError(format!("Invalid method: {e}")))?;
        let path_c = CString::new(path_and_query)
            .map_err(|e| Icd11Error::DotnetHostError(format!("Invalid path: {e}")))?;
        let body_c = match body {
            Some(b) if !b.is_empty() => Some(
                CString::new(b)
                    .map_err(|e| Icd11Error::DotnetHostError(format!("Invalid body: {e}")))?,
            ),
            _ => None,
        };
        let ct_c = match content_type {
            Some(ct) if !ct.is_empty() => Some(
                CString::new(ct)
                    .map_err(|e| Icd11Error::DotnetHostError(format!("Invalid content_type: {e}")))?,
            ),
            _ => None,
        };

        let mut status: c_int = 0;
        unsafe {
            let resp_ptr = (self.request_fn)(
                method_c.as_ptr(),
                path_c.as_ptr(),
                body_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                ct_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                &mut status,
            );
            let resp = take_string(resp_ptr, self.free_fn);
            Ok((status as u16, resp))
        }
    }

    pub fn doris(&self, release: &str, certificate_json: &str) -> Result<(u16, String), Icd11Error> {
        let release_c = CString::new(release)
            .map_err(|e| Icd11Error::DotnetHostError(format!("Invalid release: {e}")))?;
        let cert_c = CString::new(certificate_json)
            .map_err(|e| Icd11Error::DotnetHostError(format!("Invalid certificate JSON: {e}")))?;
        let mut status: c_int = 0;
        unsafe {
            let resp_ptr = (self.doris_fn)(release_c.as_ptr(), cert_c.as_ptr(), &mut status);
            let resp = take_string(resp_ptr, self.free_fn);
            Ok((status as u16, resp))
        }
    }

    pub fn codedit(
        &self,
        release: &str,
        certificate_json: &str,
    ) -> Result<(u16, String), Icd11Error> {
        let release_c = CString::new(release)
            .map_err(|e| Icd11Error::DotnetHostError(format!("Invalid release: {e}")))?;
        let cert_c = CString::new(certificate_json)
            .map_err(|e| Icd11Error::DotnetHostError(format!("Invalid certificate JSON: {e}")))?;
        let mut status: c_int = 0;
        unsafe {
            let resp_ptr = (self.codedit_fn)(release_c.as_ptr(), cert_c.as_ptr(), &mut status);
            let resp = take_string(resp_ptr, self.free_fn);
            Ok((status as u16, resp))
        }
    }

    pub fn shutdown(&self) {
        let _ = self.init_fn;
        unsafe {
            let _ = (self.shutdown_fn)();
        }
    }
}

unsafe fn resolve_method(
    load_fn: LoadAssemblyAndGetFunctionPointerFn,
    assembly_path: &CStr,
    type_name: &CStr,
    method_name: &str,
) -> Result<*mut c_void, Icd11Error> {
    let method_c = CString::new(method_name).unwrap();
    let mut fn_ptr: *mut c_void = ptr::null_mut();
    let rc = unsafe {
        load_fn(
            assembly_path.as_ptr(),
            type_name.as_ptr(),
            method_c.as_ptr(),
            UNMANAGED_CALLERS_ONLY_METHOD,
            ptr::null(),
            &mut fn_ptr,
        )
    };
    if rc < 0 || fn_ptr.is_null() {
        return Err(Icd11Error::DotnetHostError(format!(
            "Failed to resolve method {method_name} in DigitvaIcd11Bridge.dll (status 0x{rc:08x})"
        )));
    }
    Ok(fn_ptr)
}

unsafe fn take_string(ptr: *mut c_char, free_fn: BridgeFreeFn) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let s = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
    unsafe {
        free_fn(ptr);
    }
    s
}

fn path_to_cstring(p: &Path) -> Result<CString, Icd11Error> {
    CString::new(p.to_string_lossy().as_bytes())
        .map_err(|e| Icd11Error::DotnetHostError(format!("Invalid path {}: {e}", p.display())))
}

/// Discover the host `.NET` root and the newest `libhostfxr` shared library.
pub fn discover_dotnet_hostfxr() -> Result<(PathBuf, PathBuf), Icd11Error> {
    let candidates = [
        std::env::var("DOTNET_ROOT").ok().map(PathBuf::from),
        Some(PathBuf::from("/usr/local/share/dotnet")),
        Some(PathBuf::from("/opt/homebrew/opt/dotnet/libexec")),
        Some(PathBuf::from("/usr/share/dotnet")),
        Some(PathBuf::from("C:\\Program Files\\dotnet")),
    ];

    let lib_name = if cfg!(target_os = "macos") {
        "libhostfxr.dylib"
    } else if cfg!(target_os = "windows") {
        "hostfxr.dll"
    } else {
        "libhostfxr.so"
    };

    for root_opt in candidates.into_iter().flatten() {
        let fxr_dir = root_opt.join("host").join("fxr");
        if !fxr_dir.is_dir() {
            continue;
        }
        let mut versions: Vec<PathBuf> = std::fs::read_dir(&fxr_dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        versions.sort();
        for ver_dir in versions.into_iter().rev() {
            let candidate = ver_dir.join(lib_name);
            if candidate.exists() {
                return Ok((root_opt, candidate));
            }
        }
    }

    Err(Icd11Error::DotnetHostError(
        "Could not locate .NET hostfxr library (set DOTNET_ROOT if installed in a non-standard location)."
            .to_string(),
    ))
}
