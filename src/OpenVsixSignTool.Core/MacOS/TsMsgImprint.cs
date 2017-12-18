using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;

namespace OpenVsixSignTool.Core.MacOS
{
    public sealed class TsMsgImprint : IDisposable
    {
        private readonly TsMsgImprintSafeHandle _handle;
        private IntPtr _messageBufferPtr, _evp_md;
        private int _messageBufferLength;

        public TsMsgImprint()
        {
            _handle = libcrypto.TS_MSG_IMPRINT_new();
            _messageBufferPtr = IntPtr.Zero;
            _messageBufferLength = 0;
            SetDigestAlgorithm(HashAlgorithmName.SHA256);
        }

        public void SetMessage(byte[] value)
        {
            EnsureMessageBuffer(value);
            Marshal.Copy(value, 0, _messageBufferPtr, value.Length);
            AssertSuccess(libcrypto.TS_MSG_IMPRINT_set_msg(_handle, _messageBufferPtr, value.Length));
        }

        public void SetDigestAlgorithm(HashAlgorithmName hashAlgorithmName)
        {
            _evp_md = libcrypto.EVP_get_digestbyname(hashAlgorithmName.Name.ToLower());
            AssertSuccess(_evp_md);
        }

        internal TsMsgImprintSafeHandle Handle => _handle;

        public void Dispose() => Dispose(true);
        ~TsMsgImprint() => Dispose(false);

        private void Dispose(bool disposing)
        {
            GC.SuppressFinalize(this);
            if (disposing)
            {
                _handle.Dispose();
            }
            var ptr = Interlocked.Exchange(ref _messageBufferPtr, IntPtr.Zero);
            if (ptr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(ptr);
            }
            _messageBufferLength = 0;
        }

        private void EnsureMessageBuffer(byte[] message)
        {
            if (_messageBufferPtr != IntPtr.Zero && _messageBufferLength >= message.Length)
            {
                return;
            }
            if (_messageBufferPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_messageBufferPtr);
            }
            _messageBufferPtr = Marshal.AllocHGlobal(message.Length);
            _messageBufferLength = message.Length;
        }

        private static void AssertSuccess(int value, [CallerMemberNameAttribute] string caller = "")
        {
            if (value == 0)
            {
                throw new InvalidOperationException($"Platform invocation failed for {caller}.");
            }
        }

        private static void AssertSuccess(IntPtr value, [CallerMemberNameAttribute] string caller = "")
        {
            if (value == IntPtr.Zero)
            {
                throw new InvalidOperationException($"Platform invocation failed for {caller}.");
            }
        }
    }
}