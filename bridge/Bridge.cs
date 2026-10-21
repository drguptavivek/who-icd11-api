using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace DigitvaIcd11
{
    public static unsafe class Bridge
    {
        private static readonly object SyncRoot = new object();
        private static IHost _host;
        private static HttpClient _http;
        private static string _baseUrl;
        private static int _boundPort;
        private static string _bundleDir;

        private static byte* AllocUtf8(string text)
        {
            if (text == null) return null;
            return (byte*)Marshal.StringToCoTaskMemUTF8(text);
        }

        [UnmanagedCallersOnly(EntryPoint = "digitva_icd11_free", CallConvs = new[] { typeof(CallConvCdecl) })]
        public static void Free(byte* ptr)
        {
            if (ptr != null)
            {
                Marshal.FreeCoTaskMem((IntPtr)ptr);
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "digitva_icd11_init", CallConvs = new[] { typeof(CallConvCdecl) })]
        public static byte* Init(byte* bundleDirUtf8, byte* dataDirUtf8, byte* bindUrlUtf8, int* outPort)
        {
            lock (SyncRoot)
            {
                try
                {
                    if (_host != null)
                    {
                        if (outPort != null) *outPort = _boundPort;
                        return null;
                    }

                    string bundleDir = Marshal.PtrToStringUTF8((IntPtr)bundleDirUtf8);
                    string dataDir = Marshal.PtrToStringUTF8((IntPtr)dataDirUtf8);
                    string bindUrl = bindUrlUtf8 != null ? Marshal.PtrToStringUTF8((IntPtr)bindUrlUtf8) : "http://127.0.0.1:0";
                    if (string.IsNullOrWhiteSpace(bindUrl))
                    {
                        bindUrl = "http://127.0.0.1:0";
                    }

                    _bundleDir = Path.GetFullPath(bundleDir);
                    string fullDataDir = Path.GetFullPath(dataDir);

                    AssemblyLoadContext.Default.Resolving += (ctx, name) =>
                    {
                        var already = AppDomain.CurrentDomain.GetAssemblies()
                            .FirstOrDefault(a => string.Equals(a.GetName().Name, name.Name, StringComparison.OrdinalIgnoreCase));
                        if (already != null)
                        {
                            return already;
                        }
                        string candidate = Path.Combine(_bundleDir, name.Name + ".dll");
                        if (File.Exists(candidate))
                        {
                            return AssemblyLoadContext.Default.LoadFromAssemblyPath(candidate);
                        }
                        return null;
                    };

                    Environment.SetEnvironmentVariable("TMPDIR", fullDataDir);
                    Environment.SetEnvironmentVariable("TMP", fullDataDir);
                    Environment.SetEnvironmentVariable("TEMP", fullDataDir);
                    Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "container");
                    Environment.SetEnvironmentVariable("acceptLicense", "true");
                    Environment.SetEnvironmentVariable("enableDoris", "true");
                    Environment.SetEnvironmentVariable("include", "2026-01_en");
                    Environment.SetEnvironmentVariable("saveAnalytics", "false");
                    Environment.SetEnvironmentVariable("ASPNETCORE_URLS", bindUrl);
                    Directory.SetCurrentDirectory(_bundleDir);

                    StartHostInternal(_bundleDir, bindUrl, out _boundPort);
                    if (outPort != null) *outPort = _boundPort;
                    return null;
                }
                catch (Exception ex)
                {
                    return AllocUtf8(ex.ToString());
                }
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void StartHostInternal(string bundleDir, string bindUrl, out int port)
        {
            var icdAsm = AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.Combine(bundleDir, "ICD-API.dll"));
            var progType = icdAsm.GetType("ICDAPI.Program", throwOnError: true);
            var createBuilder = progType.GetMethod(
                "CreateWebHostBuilder",
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static
            );
            var builder = (IHostBuilder)createBuilder.Invoke(null, new object[] { Array.Empty<string>() });
            builder = builder.UseContentRoot(bundleDir);

            _host = builder.Build();
            _host.Start();

            var server = _host.Services.GetRequiredService<IServer>();
            var addrFeature = server.Features.Get<IServerAddressesFeature>();
            string address = addrFeature?.Addresses?.FirstOrDefault() ?? bindUrl;
            var uri = new Uri(address);
            port = uri.Port;
            _baseUrl = $"http://127.0.0.1:{port}";

            var handler = new SocketsHttpHandler
            {
                UseCookies = false,
                AllowAutoRedirect = false,
                PooledConnectionLifetime = TimeSpan.FromMinutes(15)
            };
            _http = new HttpClient(handler)
            {
                BaseAddress = new Uri(_baseUrl),
                Timeout = TimeSpan.FromSeconds(30)
            };
        }

        private static byte* RequestInternal(string method, string pathAndQuery, string bodyStr, string contentType, int* outStatus)
        {
            try
            {
                if (_http == null)
                {
                    if (outStatus != null) *outStatus = 503;
                    return AllocUtf8("{\"error\":\"ICD-11 engine not initialized\"}");
                }

                if (string.IsNullOrEmpty(method)) method = "GET";
                if (string.IsNullOrEmpty(pathAndQuery)) pathAndQuery = "/";
                if (!pathAndQuery.StartsWith("/"))
                {
                    pathAndQuery = "/" + pathAndQuery;
                }

                using var req = new HttpRequestMessage(new HttpMethod(method), pathAndQuery);
                req.Headers.TryAddWithoutValidation("API-Version", "v2");
                req.Headers.TryAddWithoutValidation("Accept", "application/json");
                req.Headers.TryAddWithoutValidation("Accept-Language", "en");

                if (!string.IsNullOrEmpty(bodyStr))
                {
                    string ct = string.IsNullOrWhiteSpace(contentType) ? "application/json" : contentType;
                    var bytes = Encoding.UTF8.GetBytes(bodyStr);
                    req.Content = new ByteArrayContent(bytes);
                    req.Content.Headers.TryAddWithoutValidation("Content-Type", ct);
                }

                using var resp = _http.Send(req);
                if (outStatus != null) *outStatus = (int)resp.StatusCode;
                string respBody = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                return AllocUtf8(respBody ?? "");
            }
            catch (Exception ex)
            {
                if (outStatus != null) *outStatus = 503;
                return AllocUtf8("{\"error\":" + System.Text.Json.JsonSerializer.Serialize(ex.Message) + "}");
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "digitva_icd11_request", CallConvs = new[] { typeof(CallConvCdecl) })]
        public static byte* Request(byte* methodUtf8, byte* pathAndQueryUtf8, byte* bodyUtf8, byte* contentTypeUtf8, int* outStatus)
        {
            string method = Marshal.PtrToStringUTF8((IntPtr)methodUtf8);
            string pathAndQuery = Marshal.PtrToStringUTF8((IntPtr)pathAndQueryUtf8);
            string body = bodyUtf8 != null ? Marshal.PtrToStringUTF8((IntPtr)bodyUtf8) : null;
            string ct = contentTypeUtf8 != null ? Marshal.PtrToStringUTF8((IntPtr)contentTypeUtf8) : null;
            return RequestInternal(method, pathAndQuery, body, ct, outStatus);
        }

        [UnmanagedCallersOnly(EntryPoint = "digitva_icd11_doris", CallConvs = new[] { typeof(CallConvCdecl) })]
        public static byte* Doris(byte* releaseUtf8, byte* certJsonUtf8, int* outStatus)
        {
            string release = Marshal.PtrToStringUTF8((IntPtr)releaseUtf8) ?? "2026-01";
            string certJson = Marshal.PtrToStringUTF8((IntPtr)certJsonUtf8) ?? "{}";
            return RequestInternal("POST", $"/icd/release/11/{release}/doris", certJson, "application/json", outStatus);
        }

        [UnmanagedCallersOnly(EntryPoint = "digitva_icd11_codedit", CallConvs = new[] { typeof(CallConvCdecl) })]
        public static byte* CodEdit(byte* releaseUtf8, byte* certJsonUtf8, int* outStatus)
        {
            string release = Marshal.PtrToStringUTF8((IntPtr)releaseUtf8) ?? "2026-01";
            string certJson = Marshal.PtrToStringUTF8((IntPtr)certJsonUtf8) ?? "{}";
            return RequestInternal("POST", $"/icd/release/11/{release}/codedit", certJson, "application/json", outStatus);
        }

        [UnmanagedCallersOnly(EntryPoint = "digitva_icd11_shutdown", CallConvs = new[] { typeof(CallConvCdecl) })]
        public static int Shutdown()
        {
            lock (SyncRoot)
            {
                try
                {
                    _http?.Dispose();
                    _http = null;
                    if (_host != null)
                    {
                        _host.StopAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
                        _host.Dispose();
                        _host = null;
                    }
                    return 0;
                }
                catch
                {
                    return -1;
                }
            }
        }
    }
}
