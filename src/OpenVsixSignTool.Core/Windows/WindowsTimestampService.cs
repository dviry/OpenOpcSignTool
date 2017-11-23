using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using OpenVsixSignTool.Core.Windows.Interop;

namespace OpenVsixSignTool.Core.Windows
{
    public class WindowsTimestampService : ITimestampService
    {
        public async Task<ErrorOr<byte[]>> SignAsync(byte[] timestampObject, Uri timestampServer, HashAlgorithmName timestampAlgorithm, TimestampNonceFactory nonce)
        {
            var oid = HashAlgorithmTranslator.TranslateFromNameToOid(timestampAlgorithm);
            var parameters = new CRYPT_TIMESTAMP_PARA
            {
                cExtension = 0,
                fRequestCerts = true
            };
            parameters.Nonce.cbData = nonce.Size;
            parameters.Nonce.pbData = nonce.NoncePointer;
            parameters.pszTSAPolicyId = null;
            var winResult = Crypt32.CryptRetrieveTimeStamp(
                timestampServer.AbsoluteUri,
                CryptRetrieveTimeStampRetrievalFlags.NONE,
                (uint)TimeSpan.FromSeconds(30).TotalMilliseconds,
                oid.Value,
                ref parameters,
                timestampObject,
                (uint)timestampObject.Length,
                out var context,
                IntPtr.Zero,
                IntPtr.Zero
            );
            if (!winResult)
            {
                return Error.From($"Timestamping failed due to error code {winResult:X2}.");
            }
            using (context)
            {
                var refSuccess = false;
                try
                {
                    context.DangerousAddRef(ref refSuccess);
                    if (!refSuccess)
                    {
                        return Error.From($"Timestamping failed due to error code {winResult:X2}.");
                    }
                    var structure = Marshal.PtrToStructure<CRYPT_TIMESTAMP_CONTEXT>(context.DangerousGetHandle());
                    var encoded = new byte[structure.cbEncoded];
                    Marshal.Copy(structure.pbEncoded, encoded, 0, encoded.Length);
                    return encoded;
                }
                finally
                {
                    if (refSuccess)
                    {
                        context.DangerousRelease();
                    }
                }
            }
        }
    }
}