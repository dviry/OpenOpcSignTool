using System;
using System.Runtime.InteropServices;

namespace OpenVsixSignTool.Core.MacOS
{
    internal sealed class TsMsgImprintSafeHandle : SafeHandle
    {
        public TsMsgImprintSafeHandle() : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            libcrypto.TS_MSG_IMPRINT_free(handle);
            return true;
        }
    }
}