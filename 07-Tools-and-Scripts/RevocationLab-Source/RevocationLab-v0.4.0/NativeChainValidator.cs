
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public sealed record NativeChainResult(
    bool ChainBuilt,
    uint ErrorStatus,
    uint InfoStatus,
    bool ValidationPassed,
    int? NativeErrorCode,
    string? NativeErrorMessage
);

public static class NativeChainValidator
{
    private const uint CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT =
        0x40000000;

    // Windows-defined pseudo-handle for the local machine chain engine.
    private static readonly IntPtr HCCE_LOCAL_MACHINE = new(1);

    public static NativeChainResult Validate(
        X509Certificate2 certificate)
    {
        var parameters = new CERT_CHAIN_PARA
        {
            cbSize = (uint)Marshal.SizeOf<CERT_CHAIN_PARA>()
        };

        IntPtr chainContext = IntPtr.Zero;

        try
        {
            bool success = CertGetCertificateChain(
                HCCE_LOCAL_MACHINE,
                certificate.Handle,
                IntPtr.Zero,
                IntPtr.Zero,
                ref parameters,
                CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
                IntPtr.Zero,
                out chainContext
            );

            if (!success)
            {
                int error = Marshal.GetLastWin32Error();

                return new NativeChainResult(
                    ChainBuilt: false,
                    ErrorStatus: 0,
                    InfoStatus: 0,
                    ValidationPassed: false,
                    NativeErrorCode: error,
                    NativeErrorMessage:
                        new Win32Exception(error).Message
                );
            }

            if (chainContext == IntPtr.Zero)
            {
                return new NativeChainResult(
                    ChainBuilt: false,
                    ErrorStatus: 0,
                    InfoStatus: 0,
                    ValidationPassed: false,
                    NativeErrorCode: null,
                    NativeErrorMessage:
                        "CryptoAPI returned a null chain context."
                );
            }

            var context =
                Marshal.PtrToStructure<CERT_CHAIN_CONTEXT>(
                    chainContext
                );

            uint errorStatus = context.TrustStatus.dwErrorStatus;
            uint infoStatus = context.TrustStatus.dwInfoStatus;

            return new NativeChainResult(
                ChainBuilt: true,
                ErrorStatus: errorStatus,
                InfoStatus: infoStatus,
                ValidationPassed: errorStatus == 0,
                NativeErrorCode: null,
                NativeErrorMessage: null
            );
        }
        finally
        {
            if (chainContext != IntPtr.Zero)
            {
                CertFreeCertificateChain(chainContext);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CERT_ENHKEY_USAGE
    {
        public uint cUsageIdentifier;
        public IntPtr rgpszUsageIdentifier;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CERT_USAGE_MATCH
    {
        public uint dwType;
        public CERT_ENHKEY_USAGE Usage;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CERT_CHAIN_PARA
    {
        public uint cbSize;
        public CERT_USAGE_MATCH RequestedUsage;
        public CERT_USAGE_MATCH RequestedIssuancePolicy;
        public uint dwUrlRetrievalTimeout;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fCheckRevocationFreshnessTime;
        public uint dwRevocationFreshnessTime;
        public IntPtr pftCacheResync;
        public IntPtr pStrongSignPara;
        public uint dwStrongSignFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CERT_TRUST_STATUS
    {
        public uint dwErrorStatus;
        public uint dwInfoStatus;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CERT_CHAIN_CONTEXT
    {
        public uint cbSize;
        public CERT_TRUST_STATUS TrustStatus;
        public uint cChain;
        public IntPtr rgpChain;
        public uint cLowerQualityChainContext;
        public IntPtr rgpLowerQualityChainContext;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fHasRevocationFreshnessTime;
        public uint dwRevocationFreshnessTime;
        public uint dwCreateFlags;
        public Guid ChainId;
    }

    [DllImport(
        "crypt32.dll",
        SetLastError = true,
        ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertGetCertificateChain(
        IntPtr hChainEngine,
        IntPtr pCertContext,
        IntPtr pTime,
        IntPtr hAdditionalStore,
        ref CERT_CHAIN_PARA pChainPara,
        uint dwFlags,
        IntPtr pvReserved,
        out IntPtr ppChainContext
    );

    [DllImport("crypt32.dll", ExactSpelling = true)]
    private static extern void CertFreeCertificateChain(
        IntPtr pChainContext
    );
}
