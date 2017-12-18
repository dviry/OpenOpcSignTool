using System;
using System.Runtime.InteropServices;

namespace OpenVsixSignTool.Core.MacOS
{
    internal sealed class TsReqSafeHandle : SafeHandle
    {
        public TsReqSafeHandle() : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            libcrypto.TS_REQ_free(handle);
            return true;
        }
    }
}