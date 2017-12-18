using System;
using System.Runtime.CompilerServices;

namespace OpenVsixSignTool.Core.MacOS
{
    internal sealed class TsRequest : IDisposable
    {
        private TsReqSafeHandle _handle;

        public TsRequest()
        {
            _handle = libcrypto.TS_REQ_new();
        }

        public int Version
        {
            get
            {
                var value = libcrypto.TS_REQ_get_version(_handle);
                return value.ToInt32();
            }
            set
            {
                AssertSuccess(libcrypto.TS_REQ_set_version(_handle, new IntPtr(value)));
            }
        }

        public bool RequestCertificate
        {
            get
            {
                return libcrypto.TS_REQ_get_cert_req(_handle);
            }
            set
            {
                AssertSuccess(libcrypto.TS_REQ_set_cert_req(_handle, value));
            }
        }

        public void Dispose()
        {
            _handle.Dispose();
        }

        public void SetMsgImprint(TsMsgImprint msgImprint)
        {
            // We do not need to take ownership of the msgimprint or increment its
            // reference count because OpenSSL will call TS_MSG_IMPRINT_dup and take
            // ownership of the duplicate.
            AssertSuccess(libcrypto.TS_REQ_set_msg_imprint(_handle, msgImprint.Handle));
        }

        private static void AssertSuccess(int value, [CallerMemberNameAttribute] string caller = "")
        {
            if (value == 0)
            {
                throw new InvalidOperationException($"Platform invocation failed for {caller}.");
            }
        }
    }
}