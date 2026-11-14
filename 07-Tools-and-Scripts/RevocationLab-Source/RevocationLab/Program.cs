
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

const string appVersion = "0.4.1";
const string cdpOid = "2.5.29.31";

Console.WriteLine($"RevocationLab v{appVersion}");
Console.WriteLine("========================");

bool forceResync =
    args.Length == 3 &&
    args[2] == "--force-resync";

if ((args.Length != 2 && args.Length != 3) ||
    args[0] != "--certificate" ||
    (args.Length == 3 && !forceResync))
{
    Console.WriteLine("Usage:");
    Console.WriteLine(
        "  RevocationLab --certificate <path-to-certificate.cer> [--force-resync]");
    return;
}

string certificatePath = Path.GetFullPath(args[1]);

if (!File.Exists(certificatePath))
{
    Console.Error.WriteLine($"Certificate not found: {certificatePath}");
    return;
}

using var certificate =
    X509CertificateLoader.LoadCertificateFromFile(certificatePath);

var cdpExtension = certificate.Extensions
    .Cast<X509Extension>()
    .FirstOrDefault(e => e.Oid?.Value == cdpOid);

var distributionPoints = new List<DistributionPointResult>();

if (cdpExtension != null)
{
    distributionPoints = DecodeCdp(cdpExtension.RawData);
}

Console.WriteLine("Starting native CryptoAPI validation...");

DateTime validationStartUtc = DateTime.UtcNow;
var stopwatch = Stopwatch.StartNew();

var chainResult = forceResync
    ? NativeChainValidator.ValidateWithResync(certificate)
    : NativeChainValidator.Validate(certificate);

stopwatch.Stop();
DateTime validationEndUtc = DateTime.UtcNow;

var result = new
{
    Application = "RevocationLab",
    Version = appVersion,
    TestId = Guid.NewGuid().ToString(),
    TimestampUtc = DateTime.UtcNow,
    ComputerName = Environment.MachineName,
    OperatingSystem = Environment.OSVersion.ToString(),
    DotNetVersion = Environment.Version.ToString(),

ProcessId = Environment.ProcessId,

Validation = new
{
    ValidationStartUtc = validationStartUtc,
    ValidationEndUtc = validationEndUtc,
    DurationMilliseconds = stopwatch.Elapsed.TotalMilliseconds,
    RevocationMode = "ChainExcludeRoot",
    CacheResyncRequested = forceResync,
    CacheMode = forceResync
        ? "CacheResync"
        : "Default",
    ChainBuilt = chainResult.ChainBuilt,
    ChainErrorStatus = $"0x{chainResult.ErrorStatus:X8}",
    ChainInfoStatus = $"0x{chainResult.InfoStatus:X8}",
    ValidationPassed = chainResult.ValidationPassed,
    NativeErrorCode = chainResult.NativeErrorCode,
    NativeErrorMessage = chainResult.NativeErrorMessage
},

    Certificate = new
    {
        Subject = certificate.Subject,
        Issuer = certificate.Issuer,
        SerialNumber = certificate.SerialNumber,
        Thumbprint = certificate.Thumbprint,
        NotBeforeUtc = certificate.NotBefore.ToUniversalTime(),
        NotAfterUtc = certificate.NotAfter.ToUniversalTime(),
        SignatureAlgorithm =
            certificate.SignatureAlgorithm.FriendlyName,

        CdpPresent = cdpExtension != null,
        CdpOid = cdpExtension?.Oid?.Value,
        CdpCritical = cdpExtension?.Critical,
        CdpRawDataHex = cdpExtension == null
            ? null
            : Convert.ToHexString(cdpExtension.RawData),

        DistributionPoints = distributionPoints
    }
};

string json = JsonSerializer.Serialize(
    result,
    new JsonSerializerOptions { WriteIndented = true }
);

Console.WriteLine(json);

string outputDirectory = Path.Combine(
    AppContext.BaseDirectory,
    "Results"
);

Directory.CreateDirectory(outputDirectory);

string outputFile = Path.Combine(
    outputDirectory,
    $"Test-{result.TestId}.json"
);

File.WriteAllText(outputFile, json);

Console.WriteLine();
Console.WriteLine($"Results saved to: {outputFile}");

static List<DistributionPointResult> DecodeCdp(byte[] rawData)
{
    var results = new List<DistributionPointResult>();

    var reader = new AsnReader(rawData, AsnEncodingRules.DER);
    var sequence = reader.ReadSequence();

    int dpIndex = 0;

    while (sequence.HasData)
    {
        dpIndex++;

        var distributionPoint = sequence.ReadSequence();
        var urls = new List<CdpUrlResult>();

        // RFC 5280:
        // DistributionPoint ::= SEQUENCE {
        //   distributionPoint [0] DistributionPointName OPTIONAL,
        //   reasons           [1] ReasonFlags OPTIONAL,
        //   cRLIssuer         [2] GeneralNames OPTIONAL
        // }

        var distributionPointTag =
            new Asn1Tag(TagClass.ContextSpecific, 0, true);

        if (distributionPoint.HasData &&
            distributionPoint.PeekTag().HasSameClassAndValue(
                distributionPointTag))
        {
            var dpName = distributionPoint.ReadSequence(
                distributionPointTag);

            // DistributionPointName ::= CHOICE {
            //   fullName                [0] GeneralNames,
            //   nameRelativeToCRLIssuer [1] RelativeDistinguishedName
            // }

            var fullNameTag =
                new Asn1Tag(TagClass.ContextSpecific, 0, true);

            if (dpName.HasData &&
                dpName.PeekTag().HasSameClassAndValue(fullNameTag))
            {
                // IMPLICIT tagging: the fullName wrapper contains
                // GeneralName elements directly.
                var generalNames = dpName.ReadSequence(fullNameTag);

                int urlIndex = 0;

                while (generalNames.HasData)
                {
                    var tag = generalNames.PeekTag();

                    // uniformResourceIdentifier [6] IA5String
                    if (tag.TagClass == TagClass.ContextSpecific &&
                        tag.TagValue == 6)
                    {
                        string url = generalNames.ReadCharacterString(
                            UniversalTagNumber.IA5String,
                            new Asn1Tag(TagClass.ContextSpecific, 6));

                        urlIndex++;

                        string protocol = Uri.TryCreate(
                            url,
                            UriKind.Absolute,
                            out var parsedUri)
                            ? parsedUri.Scheme.ToLowerInvariant()
                            : "unknown";

                        urls.Add(new CdpUrlResult(
                            urlIndex,
                            protocol,
                            url
                        ));
                    }
                    else
                    {
                        // Preserve forward compatibility with other
                        // GeneralName types.
                        generalNames.ReadEncodedValue();
                    }
                }

                generalNames.ThrowIfNotEmpty();
            }

            dpName.ThrowIfNotEmpty();
        }

        // Other optional DistributionPoint fields are not
        // interpreted yet in v0.3.0.
        while (distributionPoint.HasData)
        {
            distributionPoint.ReadEncodedValue();
        }

        results.Add(new DistributionPointResult(dpIndex, urls));
    }

    sequence.ThrowIfNotEmpty();
    reader.ThrowIfNotEmpty();

    return results;
}

public record CdpUrlResult(
    int Index,
    string Protocol,
    string Url
);

public record DistributionPointResult(
    int Index,
    List<CdpUrlResult> Urls
);
