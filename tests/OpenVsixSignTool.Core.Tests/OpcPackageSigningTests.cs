using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;
using Xunit;

namespace OpenVsixSignTool.Core.Tests
{
    public class OpcPackageSigningTests : IDisposable
    {
        private static string SamplePackage = Path.Combine("sample", "OpenVsixSignToolTest.vsix");
        private static string SamplePackageSigned = Path.Combine("sample", "OpenVsixSignToolTest-Signed.vsix");
        private readonly List<string> _shadowFiles = new List<string>();


        [Theory]
        [MemberData(nameof(RsaSigningTheories))]
        public async Task ShouldSignFileWithRsa(string pfxPath, HashAlgorithmName fileDigestAlgorithm)
        {
            string path;
            using (var package = ShadowCopyPackage(SamplePackage, out path, OpcPackageFileMode.ReadWrite))
            {
                var builder = package.CreateSignatureBuilder();
                builder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                var result = await builder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        FileDigestAlgorithm = fileDigestAlgorithm,
                        PkcsDigestAlgorithm = fileDigestAlgorithm,
                        SigningCertificate = new X509Certificate2(pfxPath, "test")
                    }
                );
                Assert.NotNull(result);
            }
        }

        [Theory]
        [MemberData(nameof(EcdsaSigningTheories))]
        public async Task ShouldSignFileWithEcdsa(string pfxPath, HashAlgorithmName fileDigestAlgorithm)
        {
            string path;
            using (var package = ShadowCopyPackage(SamplePackage, out path, OpcPackageFileMode.ReadWrite))
            {
                var builder = package.CreateSignatureBuilder();
                builder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                await builder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        FileDigestAlgorithm = fileDigestAlgorithm,
                        PkcsDigestAlgorithm = fileDigestAlgorithm,
                        SigningCertificate = new X509Certificate2(pfxPath, "test")
                    }
                );
            }
        }

        public static IEnumerable<object[]> RsaSigningTheories
        {
            get
            {
                var rsa2048Sha256 = Path.Combine("certs", "rsa-2048-sha256.pfx");
                var rsa2048Sha1 = Path.Combine("certs", "rsa-2048-sha1.pfx");
                yield return new object[] { rsa2048Sha256, HashAlgorithmName.SHA512 };
                yield return new object[] { rsa2048Sha256, HashAlgorithmName.SHA384 };
                yield return new object[] { rsa2048Sha256, HashAlgorithmName.SHA256 };
                yield return new object[] { rsa2048Sha256, HashAlgorithmName.SHA1 };
                yield return new object[] { rsa2048Sha1, HashAlgorithmName.SHA512 };
                yield return new object[] { rsa2048Sha1, HashAlgorithmName.SHA384 };
                yield return new object[] { rsa2048Sha1, HashAlgorithmName.SHA256 };
                yield return new object[] { rsa2048Sha1, HashAlgorithmName.SHA1 };
            }
        }

        public static IEnumerable<object[]> EcdsaSigningTheories
        {
            get
            {
                var ecdsap256Sha256 = Path.Combine("certs", "ecdsa-p256-sha256.pfx");
                yield return new object[] { ecdsap256Sha256, HashAlgorithmName.SHA256 };
                yield return new object[] { ecdsap256Sha256, HashAlgorithmName.SHA1 };
            }
        }

        [ConditionalTheory(supportsWindows: true)]
        [MemberData(nameof(RsaTimestampTheories))]
        public async Task ShouldTimestampFileWithRsa(string pfxPath, HashAlgorithmName timestampDigestAlgorithm)
        {
            using (var package = ShadowCopyPackage(SamplePackage, out _, OpcPackageFileMode.ReadWrite))
            {
                var signerBuilder = package.CreateSignatureBuilder();
                signerBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                var signature = await signerBuilder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        FileDigestAlgorithm = HashAlgorithmName.SHA256,
                        PkcsDigestAlgorithm = HashAlgorithmName.SHA256,
                        SigningCertificate = new X509Certificate2(pfxPath, "test")
                    }
                );
                var timestampBuilder = signature.CreateTimestampBuilder();
                var result = await timestampBuilder.SignAsync(new Uri("http://timestamp.digicert.com"), timestampDigestAlgorithm);
                Assert.Equal(TimestampResult.Success, result);
            }
        }

        [Fact]
        public async Task ShouldSupportReSigning()
        {
            string path;
            using (var package = ShadowCopyPackage(SamplePackage, out path, OpcPackageFileMode.ReadWrite))
            {
                var signerBuilder = package.CreateSignatureBuilder();
                signerBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                await signerBuilder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        PkcsDigestAlgorithm = HashAlgorithmName.SHA256,
                        FileDigestAlgorithm = HashAlgorithmName.SHA256,
                        SigningCertificate = new X509Certificate2(Path.Combine("certs", "rsa-2048-sha256.pfx"), "test")
                    }
                );
            }
            using (var package = OpcPackage.Open(path, OpcPackageFileMode.ReadWrite))
            {
                var signerBuilder = package.CreateSignatureBuilder();
                signerBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                await signerBuilder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        PkcsDigestAlgorithm = HashAlgorithmName.SHA256,
                        FileDigestAlgorithm = HashAlgorithmName.SHA256,
                        SigningCertificate = new X509Certificate2(Path.Combine("certs", "rsa-2048-sha256.pfx"), "test")
                    }
                );
            }
            using (var netfxPackage = OpcPackage.Open(path))
            {
                Assert.NotEmpty(netfxPackage.GetSignatures());
            }
        }

        [Fact]
        public async Task ShouldSupportReSigningWithDifferentCertificate()
        {
            string path;
            using (var package = ShadowCopyPackage(SamplePackage, out path, OpcPackageFileMode.ReadWrite))
            {
                var signerBuilder = package.CreateSignatureBuilder();
                signerBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                await signerBuilder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        PkcsDigestAlgorithm = HashAlgorithmName.SHA1,
                        FileDigestAlgorithm = HashAlgorithmName.SHA1,
                        SigningCertificate = new X509Certificate2(Path.Combine("certs", "rsa-2048-sha1.pfx"), "test")
                    }
                );
            }
            using (var package = OpcPackage.Open(path, OpcPackageFileMode.ReadWrite))
            {
                var signerBuilder = package.CreateSignatureBuilder();
                signerBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                await signerBuilder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        PkcsDigestAlgorithm = HashAlgorithmName.SHA256,
                        FileDigestAlgorithm = HashAlgorithmName.SHA256,
                        SigningCertificate = new X509Certificate2(Path.Combine("certs", "rsa-2048-sha256.pfx"), "test")
                    }
                );
            }
            using (var netfxPackage = OpcPackage.Open(path))
            {
                Assert.NotEmpty(netfxPackage.GetSignatures());
            }
        }

        [Fact]
        public async Task ShouldRemoveSignature()
        {
            string path;
            using (var package = ShadowCopyPackage(SamplePackage, out path, OpcPackageFileMode.ReadWrite))
            {
                var signerBuilder = package.CreateSignatureBuilder();
                signerBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                await signerBuilder.SignAsync(
                    new CertificateSignConfigurationSet
                    {
                        FileDigestAlgorithm = HashAlgorithmName.SHA1,
                        PkcsDigestAlgorithm = HashAlgorithmName.SHA1,
                        SigningCertificate = new X509Certificate2(Path.Combine("certs", "rsa-2048-sha1.pfx"), "test")
                    }
                );
            }
            using (var package = OpcPackage.Open(path, OpcPackageFileMode.ReadWrite))
            {
                var signatures = package.GetSignatures().ToList();
                Assert.Single(signatures);
                var signature = signatures[0];
                signature.Remove();
                Assert.Null(signature.Part);
                Assert.Throws<InvalidOperationException>(() => signature.CreateTimestampBuilder());
                Assert.Empty(package.GetSignatures());
            }
        }

        public static IEnumerable<object[]> RsaTimestampTheories
        {
            get
            {
                var rsa2048Sha256 = Path.Combine("certs", "rsa-2048-sha256.pfx");
                var rsa2048Sha1 = Path.Combine("certs", "rsa-2048-sha1.pfx");
                yield return new object[] { rsa2048Sha256, HashAlgorithmName.SHA256 };
                yield return new object[] { rsa2048Sha256, HashAlgorithmName.SHA1 };
                yield return new object[] { rsa2048Sha1, HashAlgorithmName.SHA256 };
                yield return new object[] { rsa2048Sha1, HashAlgorithmName.SHA1 };
            }
        }

        private OpcPackage ShadowCopyPackage(string packagePath, out string path, OpcPackageFileMode mode = OpcPackageFileMode.Read)
        {
            var temp = Path.GetTempFileName();
            _shadowFiles.Add(temp);
            File.Copy(packagePath, temp, true);
            path = temp;
            return OpcPackage.Open(temp, mode);
        }

        public void Dispose()
        {
            void CleanUpShadows()
            {
                _shadowFiles.ForEach(File.Delete);
            }
            CleanUpShadows();
        }
    }
}
