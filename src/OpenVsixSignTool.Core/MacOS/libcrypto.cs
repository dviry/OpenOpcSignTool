using System;
using System.Runtime.InteropServices;

namespace OpenVsixSignTool.Core.MacOS
{
    internal static class libcrypto
    {
        static libcrypto()
        {
            OpenSSL_add_all_digests();
        }

        private const string LibSslBinary = "libcrypto.41";

        [method: DllImport(LibSslBinary, EntryPoint = "OpenSSL_add_all_digests", CallingConvention = CallingConvention.Cdecl)]
        public static extern void OpenSSL_add_all_digests();

        [method: DllImport(LibSslBinary, EntryPoint = "TS_REQ_new", CallingConvention = CallingConvention.Cdecl)]
        public static extern TsReqSafeHandle TS_REQ_new();

        [method: DllImport(LibSslBinary, EntryPoint = "TS_REQ_free", CallingConvention = CallingConvention.Cdecl)]
        public static extern void TS_REQ_free
        (
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr a
        );

        [return: MarshalAs(UnmanagedType.I4)]
        [method: DllImport(LibSslBinary, EntryPoint = "TS_REQ_set_version", CallingConvention = CallingConvention.Cdecl)]
        public static extern int TS_REQ_set_version
        (
            [param: In] TsReqSafeHandle a,
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr version
        );

        [return: MarshalAs(UnmanagedType.SysInt)]
        [method: DllImport(LibSslBinary, EntryPoint = "TS_REQ_get_version", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr TS_REQ_get_version
        (
            [param: In] TsReqSafeHandle a
        );

        [return: MarshalAs(UnmanagedType.I4)]
        [method: DllImport(LibSslBinary, EntryPoint = "TS_REQ_set_cert_req", CallingConvention = CallingConvention.Cdecl)]
        public static extern int TS_REQ_set_cert_req
        (
            [param: In] TsReqSafeHandle a,
            [param: In, MarshalAs(UnmanagedType.Bool)] bool cert_req
        );

        [return: MarshalAs(UnmanagedType.Bool)]
        [method: DllImport(LibSslBinary, EntryPoint = "TS_REQ_get_cert_req", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool TS_REQ_get_cert_req
        (
            [param: In] TsReqSafeHandle a
        );

        [method: DllImport(LibSslBinary, EntryPoint = "TS_MSG_IMPRINT_free", CallingConvention = CallingConvention.Cdecl)]
        public static extern void TS_MSG_IMPRINT_free
        (
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr a
        );


        [method: DllImport(LibSslBinary, EntryPoint = "TS_MSG_IMPRINT_new", CallingConvention = CallingConvention.Cdecl)]
        public static extern TsMsgImprintSafeHandle TS_MSG_IMPRINT_new();

        [return: MarshalAs(UnmanagedType.I4)]
        [method: DllImport(LibSslBinary, EntryPoint = "TS_REQ_set_msg_imprint", CallingConvention = CallingConvention.Cdecl)]
        public static extern int TS_REQ_set_msg_imprint
        (
            [param: In] TsReqSafeHandle a,
            [param: In] TsMsgImprintSafeHandle msg_imprint
        );

        [return: MarshalAs(UnmanagedType.I4)]
        [method: DllImport(LibSslBinary, EntryPoint = "TS_MSG_IMPRINT_set_msg", CallingConvention = CallingConvention.Cdecl)]
        public static extern int TS_MSG_IMPRINT_set_msg
        (
            [param: In] TsMsgImprintSafeHandle a,
            [param: In, MarshalAs(UnmanagedType.SysInt)] IntPtr d,
            [param: In, MarshalAs(UnmanagedType.I4)] int len
        );

        [return: MarshalAs(UnmanagedType.SysInt)]
        [method: DllImport(LibSslBinary, EntryPoint = "EVP_get_digestbyname", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr EVP_get_digestbyname
        (
            [param: In, MarshalAs(UnmanagedType.LPStr)] string name
        );
    }
}