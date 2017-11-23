using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OpenVsixSignTool.Core
{
    public class TimestampNonceFactory : IDisposable
    {
        private readonly IntPtr _nativeMemory;
        private readonly uint _nonceSize;
        private readonly byte[] _nonce;

        public TimestampNonceFactory(int nonceSize = 32)
        {
            _nativeMemory = Marshal.AllocCoTaskMem(nonceSize);
            _nonceSize = checked((uint)nonceSize);
            _nonce = new byte[nonceSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(_nonce);
            }
            //The nonce is technically an integer. Some timestamp servers may not like a "negative" nonce. Clear the sign bit so it's positive.
            //That loses one bit of entropy, however is well within the security boundary of a properly sized nonce. Authenticode doesn't even use
            //a nonce.
            _nonce[_nonce.Length - 1] &= 0b01111111;
            Marshal.Copy(_nonce, 0, _nativeMemory, _nonce.Length);
        }

        internal IntPtr NoncePointer => _nativeMemory;
        internal byte[] Nonce => _nonce;
        public uint Size => _nonceSize;

        public void Dispose()
        {
            Marshal.FreeCoTaskMem(_nativeMemory);
        }
    }
}
