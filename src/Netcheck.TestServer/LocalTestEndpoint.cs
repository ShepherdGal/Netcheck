using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;

namespace Netcheck.TestServer;

public sealed class LocalTestEndpoint : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly X509Certificate2 _certificate;

    private LocalTestEndpoint(WebApplication app, X509Certificate2 certificate)
    {
        _app = app;
        _certificate = certificate;
        Address = new Uri(app.Urls.Single());
        CertificateHash = certificate.GetCertHash(HashAlgorithmName.SHA256);
        using var key = certificate.GetECDsaPublicKey()
            ?? throw new InvalidOperationException("The loopback certificate has no ECDSA public key.");
        PublicKeyPin = "sha256//" + Convert.ToBase64String(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
    }

    public Uri Address { get; }
    public byte[] CertificateHash { get; }
    public string PublicKeyPin { get; }

    public static async Task<LocalTestEndpoint> StartAsync(CancellationToken cancellationToken, int? bytesPerSecond = null,
        TimeSpan? probeDelay = null, Func<bool>? interruptTransfers = null)
    {
        var certificate = CreateCertificate();
        WebApplication? app = null;
        try
        {
            app = TestEndpoint.Build([], certificate, bytesPerSecond, probeDelay, interruptTransfers);
            await app.StartAsync(cancellationToken).ConfigureAwait(false);
            return new LocalTestEndpoint(app, certificate);
        }
        catch
        {
            if (app is not null)
                await app.DisposeAsync().ConfigureAwait(false);
            certificate.Dispose();
            throw;
        }
    }

    internal static X509Certificate2 CreateCertificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        var now = DateTimeOffset.UtcNow;
        using var generated = request.CreateSelfSigned(now.AddMinutes(-1), now.AddHours(1));
        var pfx = generated.Export(X509ContentType.Pkcs12);
        try
        {
            // Schannel needs a user key container. No certificate is added to a trust store.
            var flags = OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet;
            return X509CertificateLoader.LoadPkcs12(pfx, null, flags);
        }
        finally { CryptographicOperations.ZeroMemory(pfx); }
    }

    public async ValueTask DisposeAsync()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try { await _app.StopAsync(deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
        finally
        {
            await _app.DisposeAsync().ConfigureAwait(false);
            _certificate.Dispose();
        }
    }
}
