using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;

namespace OpenVsixSignTool.Core.Tests
{
    public class CertificateSigningContextTests
    {
        [Theory]
        [MemberData(nameof(RsaCertificateTheories))]
        public async Task ShouldSignABlobOfDataWithRsaSha256(string pfxPath)
        {
            var certificate = new X509Certificate2(pfxPath, "test");
            using (var context = new CertificateSigningContext(certificate, HashAlgorithmName.SHA256, HashAlgorithmName.SHA256))
            {
                using (var hash = SHA256.Create())
                {
                    var digest = hash.ComputeHash(new byte[] { 1, 2, 3 });
                    var signature = await context.SignDigestAsync(digest);
                    Assert.Equal(OpcKnownUris.SignatureAlgorithms.rsaSHA256, context.XmlDSigIdentifier);
                    Assert.Equal(SigningAlgorithm.RSA, context.SignatureAlgorithm);

                    var roundtrips = await context.VerifyDigestAsync(digest, signature);
                    Assert.True(roundtrips);
                }
            }
        }

        [Theory]
        [MemberData(nameof(RsaCertificateTheories))]
        public async Task ShouldSignABlobOfDataWithRsaSha1(string pfxPath)
        {
            var certificate = new X509Certificate2(pfxPath, "test");
            using (var context = new CertificateSigningContext(certificate, HashAlgorithmName.SHA1, HashAlgorithmName.SHA1))
            {
                using (var hash = SHA1.Create())
                {
                    var digest = hash.ComputeHash(new byte[] { 1, 2, 3 });
                    var signature = await context.SignDigestAsync(digest);
                    Assert.Equal(OpcKnownUris.SignatureAlgorithms.rsaSHA1, context.XmlDSigIdentifier);
                    Assert.Equal(SigningAlgorithm.RSA, context.SignatureAlgorithm);

                    var roundtrips = await context.VerifyDigestAsync(digest, signature);
                    Assert.True(roundtrips);
                }
            }
        }

        [Theory]
        [MemberData(nameof(EcdsaCertificateTheories))]
        public async Task ShouldSignABlobOfDataWithEcdsaP256Sha256(string pfxPath)
        {
            var certificate = new X509Certificate2(pfxPath, "test");
            using (var context = new CertificateSigningContext(certificate, HashAlgorithmName.SHA256, HashAlgorithmName.SHA256))
            {
                using (var hash = SHA256.Create())
                {
                    var digest = hash.ComputeHash(new byte[] { 1, 2, 3 });
                    var signature = await context.SignDigestAsync(digest);
                    Assert.Equal(OpcKnownUris.SignatureAlgorithms.ecdsaSHA256, context.XmlDSigIdentifier);
                    Assert.Equal(SigningAlgorithm.ECDSA, context.SignatureAlgorithm);

                    var roundtrips = await context.VerifyDigestAsync(digest, signature);
                    Assert.True(roundtrips);
                }
            }
        }

        public static IEnumerable<object[]> RsaCertificateTheories
        {
            get
            {
                var rsa2048Sha256 = Path.Combine("certs", "rsa-2048-sha256.pfx");
                var rsa2048Sha1 = Path.Combine("certs", "rsa-2048-sha1.pfx");
                yield return new object[] { rsa2048Sha256 };
                yield return new object[] { rsa2048Sha1 };
            }
        }

        public static IEnumerable<object[]> EcdsaCertificateTheories
        {
            get
            {
                yield return new object[] { Path.Combine("certs", "ecdsa-p256-sha256.pfx") };
            }
        }
    }
}
