using System;
using System.Security.Cryptography;
using OpenVsixSignTool.Core.MacOS;
using Xunit;

namespace OpenVsixSignTool.Core.Tests
{
    public class LibcryptoTests
    {
        [ConditionalFact(supportsMacOS: true)]
        public void ShouldRoundtripVersion()
        {
            using(var request = new TsRequest())
            {
                request.Version = 1;
                Assert.Equal(1, request.Version);
            }
        }

        [ConditionalFact(supportsMacOS: true)]
        public void ShouldRoundtripCertificateRequest()
        {
            using(var request = new TsRequest())
            {
                request.RequestCertificate = true;
                Assert.True(request.RequestCertificate);

                request.RequestCertificate = false;
                Assert.False(request.RequestCertificate);
            }
        }

        [ConditionalFact(supportsMacOS: true)]
        public void ShouldSetMessageImprintSuccessfully()
        {
            for (var i = 0; i < 1000; i ++)
            using(var request = new TsRequest())
            {
                using (var imprint = new TsMsgImprint())
                {
                    using (HashAlgorithm sha256 = SHA256.Create(), sha512 = SHA512.Create())
                    {
                        var digest256 = sha256.ComputeHash(new byte[] { 1 });
                        var digest512 = sha512.ComputeHash(new byte[] { 1 });
                        imprint.SetDigestAlgorithm(HashAlgorithmName.SHA256);
                        imprint.SetMessage(digest256);
                        imprint.SetDigestAlgorithm(HashAlgorithmName.SHA512);
                        imprint.SetMessage(digest512);
                    }
                }
            }
        }

        [Fact]
        public void ShouldNotExplodeOnDoubleDispose()
        {
            var imprint = new TsMsgImprint();
            imprint.SetDigestAlgorithm(HashAlgorithmName.SHA256);
            imprint.Dispose();
            imprint.Dispose();
        }
    }
}