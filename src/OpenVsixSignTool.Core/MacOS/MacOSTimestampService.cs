using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace OpenVsixSignTool.Core.MacOS
{
    public sealed class MacOSTimestampService : ITimestampService
    {
        private static readonly HttpClient _client;

        static MacOSTimestampService()
        {
            _client = new HttpClient();
        }

        public async Task<ErrorOr<byte[]>> SignAsync(byte[] timestampObject, Uri timestampServer, HashAlgorithmName timestampAlgorithm, TimestampNonceFactory nonce)
        {
            var oid = HashAlgorithmTranslator.TranslateFromNameToOid(timestampAlgorithm);
            byte[] digest;
            using (var hashAlgorithm = HashAlgorithmTranslator.TranslateFromNameToxmlDSigUri(timestampAlgorithm, out var _))
            {
                digest = hashAlgorithm.ComputeHash(timestampObject);
            }
            byte[] timestampRequest = Array.Empty<byte>();
            var content = new ByteArrayContent(timestampRequest);
            content.Headers.Add("Content-Type", "application/timestamp-query");
            var response = await _client.PostAsync(timestampServer, content);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                return Error.From("Timestamp server did not respond successfully.");
            }
            var timestamp = await response.Content.ReadAsByteArrayAsync();
            return Array.Empty<byte>();
        }
    }
}