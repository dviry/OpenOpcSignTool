using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace OpenVsixSignTool.Core
{
    /// <summary>
    /// A builder for adding timestamps to a package.
    /// </summary>
    public class OpcPackageTimestampBuilder
    {
        private readonly OpcPart _part;

        internal OpcPackageTimestampBuilder(OpcPart part)
        {
            _part = part;
            Timeout = TimeSpan.FromSeconds(30);
        }

        /// <summary>
        /// Gets or sets the timeout for signing the package.
        /// The default is 30 earth seconds.
        /// </summary>
        public TimeSpan Timeout { get; set; }

        /// <summary>
        /// Signs the package with a timestamp.
        /// </summary>
        /// <param name="timestampServer">The URI of the timestamp server.</param>
        /// <param name="timestampAlgorithm">The hash algorithm to timestamp with.</param>
        /// <returns>A result of the timestamp operation.</returns>
        public async Task<TimestampResult> SignAsync(Uri timestampServer, HashAlgorithmName timestampAlgorithm)
        {
            if (timestampServer == null)
            {
                throw new ArgumentNullException(nameof(timestampServer));
            }
            if (!timestampServer.IsAbsoluteUri)
            {
                throw new ArgumentException("The timestamp server must be an absolute URI.", nameof(timestampServer));
            }
            using (var nonce = new TimestampNonceFactory())
            {
                var service = TimestampServiceFactory.GetTimestampService();
                var (signatureDocument, timestampSubject) = GetSignatureToTimestamp(_part);
                var signature = await service.SignAsync(timestampSubject, timestampServer, timestampAlgorithm, nonce);
                switch (signature)
                {
                    case ErrorOr<byte[]>.Ok signatureBytes:
                        ApplyTimestamp(signatureDocument, _part, signatureBytes.Value);
                        return TimestampResult.Success;
                    default:
                    case ErrorOr<byte[]>.Err err:
                        return TimestampResult.Failed;
                }
            }
        }

        private static (XDocument document, byte[] signature) GetSignatureToTimestamp(OpcPart signaturePart)
        {
            XNamespace xmlDSigNamespace = OpcKnownUris.XmlDSig.AbsoluteUri;
            using (var signatureStream = signaturePart.Open())
            {
                var doc = XDocument.Load(signatureStream);
                var signature = doc.Element(xmlDSigNamespace + "Signature")?.Element(xmlDSigNamespace + "SignatureValue")?.Value?.Trim();
                return (doc, Convert.FromBase64String(signature));
            }
        }

        private static void ApplyTimestamp(XDocument originalSignatureDocument, OpcPart signaturePart, byte[] timestampSignature)
        {
            XNamespace xmlDSigNamespace = OpcKnownUris.XmlDSig.AbsoluteUri;
            XNamespace xmlSignatureNamespace = OpcKnownUris.XmlDigitalSignature.AbsoluteUri;
            var document = new XDocument(originalSignatureDocument);
            var signature = new XElement(xmlDSigNamespace + "Object",
                new XElement(xmlSignatureNamespace + "TimeStamp", new XAttribute("Id", "idSignatureTimestamp"),
                    new XElement(xmlSignatureNamespace + "Comment", ""),
                    new XElement(xmlSignatureNamespace + "EncodedTime", Convert.ToBase64String(timestampSignature))
                )
            );
            document.Element(xmlDSigNamespace + "Signature").Add(signature);
            using (var copySignatureStream = signaturePart.Open())
            {
                using (var xmlWriter = new XmlTextWriter(copySignatureStream, System.Text.Encoding.UTF8))
                {
                    //The .NET implementation of OPC used by Visual Studio does not tollerate "white space" nodes.
                    xmlWriter.Formatting = Formatting.None;
                    document.Save(xmlWriter);
                }
            }
        }
    }
}
