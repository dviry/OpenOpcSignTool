using System;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace OpenVsixSignTool.Core
{
    public interface ITimestampService
    {
        Task<ErrorOr<byte[]>> SignAsync(byte[] signingObject, Uri timestampServer, HashAlgorithmName timestampAlgorithm, TimestampNonceFactory nonce);
    }
}