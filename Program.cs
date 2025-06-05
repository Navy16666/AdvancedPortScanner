using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PdfSharp.Pdf;
using PdfSharp.Drawing;
using static System.Net.Mime.MediaTypeNames;
using System.Xml.Linq;
using System.IO;
using PdfSharp.Fonts;

namespace AdvancedPortScanner
{
    internal class CustomFontResolver : IFontResolver
    {
        public string DefaultFontName => "Arial";

        public byte[] GetFont(string faceName)
        {
            try
            {
                var fontPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Fonts", "arial.ttf");
                if (File.Exists(fontPath))
                {
                    return File.ReadAllBytes(fontPath);
                }

                return new byte[0];
            }
            catch
            {
                return new byte[0];
            }
        }

        public FontResolverInfo ResolveTypeface(string familyName, bool isBold, bool isItalic)
        {
            return new FontResolverInfo("Arial");
        }
    }

    internal class Program
    {
        private static readonly Dictionary<int, PortScanResult> scanResults = new();
        private static readonly object scanResultsLock = new();
        private static readonly SemaphoreSlim semaphore = new(100);

        private static int totalPorts;
        private static int completedPorts;

        private static string? scannedHost;

        private static readonly Dictionary<int, string> commonPorts = new()
        {
            { 21, "FTP" },
            { 22, "SSH" },
            { 23, "Telnet" },
            { 25, "SMTP" },
            { 53, "DNS" },
            { 80, "HTTP" },
            { 110, "POP3" },
            { 143, "IMAP" },
            { 443, "HTTPS" },
            { 445, "SMB" },
            { 1433, "MSSQL" },
            { 3306, "MySQL" },
            { 3389, "RDP" },
            { 5432, "PostgreSQL" },
            { 5900, "VNC" },
            { 6379, "Redis" },
            { 8080, "HTTP-Proxy" },
            { 8443, "HTTPS-Alt" },
            { 27017, "MongoDB" }
        };

        private static readonly Dictionary<int, string> portToService = new()
        {
            { 1, "TCP Port Service Multiplexer" },
            { 2, "CompressNET" },
            { 3, "CompressNET" },
            { 5, "Remote Job Entry" },
            { 7, "Echo" },
            { 9, "Discard" },
            { 11, "SYSTAT" },
            { 13, "Daytime" },
            { 17, "Quote of the Day" },
            { 19, "Character Generator" },
            { 20, "FTP Data" },
            { 21, "FTP" },
            { 22, "SSH" },
            { 23, "Telnet" },
            { 25, "SMTP" },
            { 37, "Time" },
            { 39, "RLP" },
            { 42, "WINS Replication" },
            { 43, "WHOIS" },
            { 49, "TACACS" },
            { 53, "DNS" },
            { 67, "DHCP Server" },
            { 68, "DHCP Client" },
            { 69, "TFTP" },
            { 70, "Gopher" },
            { 79, "Finger" },
            { 80, "HTTP" },
            { 81, "Torpark Onion Routing" },
            { 82, "XFER Utility" },
            { 88, "Kerberos" },
            { 110, "POP3" },
            { 111, "RPCbind" },
            { 113, "Ident" },
            { 119, "NNTP" },
            { 123, "NTP" },
            { 135, "MS RPC" },
            { 137, "NetBIOS Name" },
            { 138, "NetBIOS Datagram" },
            { 139, "NetBIOS Session" },
            { 143, "IMAP" },
            { 161, "SNMP" },
            { 162, "SNMP Trap" },
            { 179, "BGP" },
            { 194, "IRC" },
            { 389, "LDAP" },
            { 443, "HTTPS" },
            { 445, "Microsoft-DS" },
            { 465, "SMTPS" },
            { 514, "Syslog" },
            { 515, "Printer" },
            { 520, "RIP" },
            { 587, "Submission" },
            { 631, "IPP" },
            { 666, "Doom" },
            { 993, "IMAPS" },
            { 995, "POP3S" },
            { 1080, "SOCKS" },
            { 1433, "MSSQL" },
            { 1521, "Oracle DB" },
            { 1723, "PPTP" },
            { 2049, "NFS" },
            { 2082, "cPanel" },
            { 2083, "cPanel SSL" },
            { 2100, "Oracle XDB" },
            { 2222, "DirectAdmin" },
            { 2375, "Docker" },
            { 2376, "Docker SSL" },
            { 2483, "Oracle DB" },
            { 2484, "Oracle DB SSL" },
            { 3306, "MySQL" },
            { 3389, "RDP" },
            { 3690, "Subversion" },
            { 4000, "ICQ" },
            { 5432, "PostgreSQL" },
            { 5900, "VNC" },
            { 6379, "Redis" },
            { 6667, "IRC" },
            { 7001, "WebLogic" },
            { 8000, "Common HTTP Alt" },
            { 8080, "HTTP-Proxy" },
            { 8081, "HTTP Alt" },
            { 8443, "HTTPS-Alt" },
            { 8888, "Alternate HTTP" },
            { 9000, "SonarQube" },
            { 9200, "Elasticsearch" },
            { 11211, "Memcached" },
            { 1352, "Lotus Notes" },
            { 1434, "MSSQL Monitor" },
            { 1812, "RADIUS" },
            { 1813, "RADIUS Accounting" },
            { 2000, "Cisco SCCP" },
            { 2221, "ESET Antivirus" },
            { 2379, "etcd Client" },
            { 2380, "etcd Server" },
            { 25565, "Minecraft" },
            { 27017, "MongoDB" },
            { 27018, "MongoDB" },
            { 27019, "MongoDB" },
            { 28017, "MongoDB Web" },
            { 3000, "Node.js/React/Dev" },
            { 3128, "Squid Proxy" },
            { 33060, "MySQL X Protocol" },
            { 3388, "CB Server" },
            { 4369, "Erlang Port Mapper" },
            { 5000, "UPnP/WebDAV" },
            { 5001, "commplex-link" },
            { 5433, "PostgreSQL Alt" },
            { 5672, "RabbitMQ" },
            { 5683, "CoAP" },
            { 5901, "VNC Alt" },
            { 5984, "CouchDB" },
            { 7000, "Cassandra" },
            { 7002, "Cassandra" },
            { 7199, "Cassandra JMX" },
            { 8008, "HTTP Alt" },
            { 8086, "InfluxDB" },
            { 8091, "Couchbase" },
            { 8444, "HTTPS Alt" },
            { 8500, "Consul" },
            { 8765, "Ultravnc" },
            { 8834, "Nessus" },
            { 8880, "Alternate HTTP" },
            { 9418, "Git" },
            { 9999, "Urchin" },
            { 10000, "Webmin" },
            { 11214, "Memcached" },
            { 11215, "Memcached" },
            { 50000, "DB2" },
            { 50070, "Hadoop NameNode" },
            { 50075, "Hadoop DataNode" },
            { 61616, "ActiveMQ" },
            { 49152, "Windows RPC" },
            { 49153, "Windows RPC" },
            { 49154, "Windows RPC" },
            { 49155, "Windows RPC" },
            { 49156, "Windows RPC" },
            { 49157, "Windows RPC" },
            { 49158, "Windows RPC" },
            { 49159, "Windows RPC" },
            { 49160, "Windows RPC" },
            { 49161, "Windows RPC" },
            { 49162, "Windows RPC" }
        };

        static async Task Main(string[] args)
        {
            var parsedArgs = ParseArgs(args);

            string? host = GetArg(parsedArgs, "host") ?? Prompt("Enter host to scan:");
            scannedHost = host;
            string? portRangeInput = GetArg(parsedArgs, "ports") ?? Prompt("Enter ports (Example. 80 or 443 or 100-120):");

            var ports = ParsePortRange(portRangeInput);
            totalPorts = ports.Count;

            Console.WriteLine($"Logical processors: {Environment.ProcessorCount}");
            Console.WriteLine($"ThreadPool min threads: {GetMinThreadPool()}");

            StartHttpServer();
            OpenBrowser("http://localhost:8888");

            var stopwatch = Stopwatch.StartNew();

            var options = new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount };
            await Task.Run(() => Parallel.ForEach(ports, options, port => ScanPortWithRetriesAsync(host, port).Wait()));

            stopwatch.Stop();

            Console.WriteLine($"\nScan completed in {stopwatch.ElapsedMilliseconds} ms");
            Console.WriteLine("Press Enter to stop the server and exit.");
            Console.ReadLine();
        }

        private static async Task ScanPortWithRetriesAsync(string host, int port)
        {
            const int maxRetries = 3;
            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                bool success = await ScanPortAsync(host, port);
                if (success) break;
                await Task.Delay(250 * attempt);
            }

            Interlocked.Increment(ref completedPorts);
            DisplayProgress();
        }

        private static async Task<bool> ScanPortAsync(string host, int port)
        {
            await semaphore.WaitAsync();
            try
            {
                using var client = new TcpClient();
                using var cts = new CancellationTokenSource(5000); 
                await client.ConnectAsync(host, port, cts.Token);

                string? service = portToService.TryGetValue(port, out var svc) ? svc : "Unknown";
                lock (scanResultsLock)
                {
                    scanResults[port] = new PortScanResult(port, "Open", service);
                }

                return true;
            }
            catch (SocketException)
            {
                string? service = portToService.TryGetValue(port, out var svc) ? svc : "Unknown";
                lock (scanResultsLock) { scanResults[port] = new PortScanResult(port, "Closed", service); }
            }
            catch (OperationCanceledException)
            {
                string? service = portToService.TryGetValue(port, out var svc) ? svc : "Unknown";
                lock (scanResultsLock) { scanResults[port] = new PortScanResult(port, "Timeout", service); }
            }
            catch (Exception)
            {
                string? service = portToService.TryGetValue(port, out var svc) ? svc : "Unknown";
                lock (scanResultsLock) { scanResults[port] = new PortScanResult(port, "Error", service); }
            }
            finally
            {
                semaphore.Release();
            }
            return false;
        }

        private static List<int> ParsePortRange(string input)
        {
            var ports = new List<int>();
            foreach (var part in input.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                if (part.Contains('-'))
                {
                    var range = part.Split('-');
                    if (int.TryParse(range[0], out int start) && int.TryParse(range[1], out int end))
                        ports.AddRange(Enumerable.Range(start, end - start + 1));
                }
                else if (int.TryParse(part, out int singlePort))
                {
                    ports.Add(singlePort);
                }
            }
            return ports.Distinct().OrderBy(p => p).ToList();
        }

        private static void DisplayProgress()
        {
            double percent = (double)completedPorts / totalPorts * 100;
            Console.CursorLeft = 0;
            Console.Write($"Progress: {percent:F2}%");
        }

        private static string GenerateHtmlPageWithExports()
        {
            double percent;
            int totalOpenPorts = 0;
            int totalClosedPorts = 0;
            int totalTimeoutPorts = 0;
            int totalErrorPorts = 0;

            lock (scanResultsLock)
            {
                percent = totalPorts == 0 ? 0 : (double)completedPorts / totalPorts * 100;
                totalOpenPorts = scanResults.Values.Count(r => r.Status == "Open");
                totalClosedPorts = scanResults.Values.Count(r => r.Status == "Closed");
                totalTimeoutPorts = scanResults.Values.Count(r => r.Status == "Timeout");
                totalErrorPorts = scanResults.Values.Count(r => r.Status == "Error");
            }

            var html = new StringBuilder();
            html.AppendLine("<html><head>");

            if (percent < 100)
            {
                html.AppendLine("<meta http-equiv='refresh' content='2'>");
            }

            html.AppendLine("<style>");
            html.AppendLine(@"
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
        }
        h2 {
            color: #fff;
            text-align: center;
            margin-bottom: 20px;
            text-shadow: 1px 1px 3px rgba(0,0,0,0.3);
        }
        .progress {
            font-size: 1.4em;
            font-weight: 600;
            margin-bottom: 15px;
            color: #fff;
            text-align: center;
            animation: pulse 2s infinite;
        }
        .summary {
            background: rgba(255, 255, 255, 0.9);
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .summary h3 {
            margin-top: 0;
            color: #5a2a83;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 10px;
        }
        .summary-item {
            padding: 10px;
            border-radius: 5px;
            text-align: center;
        }
        .summary-item.open { background-color: #27ae60; color: white; }
        .summary-item.closed { background-color: #c0392b; color: white; }
        .summary-item.timeout { background-color: #e67e22; color: white; }
        .summary-item.error { background-color: #7f8c8d; color: white; }
        @keyframes pulse {
            0% { opacity: 0.7; }
            50% { opacity: 1; }
            100% { opacity: 0.7; }
        }
        table {
            border-collapse: collapse;
            width: 100%;
            background: #fff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            animation: fadeIn 1s ease-in;
            margin-top: 20px;
        }
        th, td {
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
            text-align: left;
            font-size: 0.95em;
        }
        th {
            background-color: #5a2a83;
            color: white;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            position: sticky;
            top: 0;
        }
        tr:hover {
            background-color: #f1f1f1;
            transition: background-color 0.3s ease;
        }
        .status {
            font-weight: 600;
            padding: 5px 10px;
            border-radius: 4px;
            display: inline-block;
        }
        .status.open { background-color: #27ae60; color: white; }
        .status.closed { background-color: #c0392b; color: white; }
        .status.timeout { background-color: #e67e22; color: white; }
        .status.error { background-color: #7f8c8d; color: white; }
        .service {
            font-weight: 500;
            color: #5a2a83;
        }
        .exports {
            margin: 20px 0;
            text-align: center;
        }
        .exports button {
            background-color: #764ba2;
            border: none;
            color: white;
            padding: 10px 20px;
            margin: 0 10px;
            border-radius: 25px;
            font-size: 1em;
            cursor: pointer;
            box-shadow: 0 4px 6px rgba(118, 75, 162, 0.6);
            transition: background-color 0.3s ease;
        }
        .exports button:hover {
            background-color: #5a2a83;
        }
        @keyframes fadeIn {
            from {opacity: 0;}
            to {opacity: 1;}
        }
    ");
            html.AppendLine("</style></head><body>");

            html.AppendLine($"<div class='progress'><b>Progress:</b> {percent:F2}%</div>");
            html.AppendLine("<h2>Advanced Port Scanner Report</h2>");

            html.AppendLine("<div class='summary'>");
            html.AppendLine("<h3>Scan Summary</h3>");
            html.AppendLine("<div class='summary-grid'>");
            html.AppendLine($"<div class='summary-item open'>Open Ports: {totalOpenPorts}</div>");
            html.AppendLine($"<div class='summary-item closed'>Closed Ports: {totalClosedPorts}</div>");
            html.AppendLine($"<div class='summary-item timeout'>Timeout Ports: {totalTimeoutPorts}</div>");
            html.AppendLine($"<div class='summary-item error'>Error Ports: {totalErrorPorts}</div>");
            html.AppendLine("</div></div>");

            html.AppendLine("<div class='exports'>");
            html.AppendLine("<button onclick=\"window.location.href='/export/pdf'\">Export as PDF</button>");
            html.AppendLine("<button onclick=\"window.location.href='/export/excel'\">Export as Excel</button>");
            html.AppendLine("<button onclick=\"window.location.href='/export/text'\">Export as Text</button>");
            html.AppendLine("</div>");

            html.AppendLine("<table>");
            html.AppendLine("<tr><th>IP:Port</th><th>Status</th><th>Service</th></tr>");

            lock (scanResultsLock)
            {
                foreach (var r in scanResults.Values.OrderBy(r => r.Port))
                {
                    string statusClass = r.Status.ToLower();
                    string service = r.Service ?? "Unknown";

                    html.AppendLine($@"<tr>
                        <td>{scannedHost}:{r.Port}</td>
                        <td><span class='status {statusClass}'>{r.Status}</span></td>
                        <td class='service'>{WebUtility.HtmlEncode(service)}</td>
                    </tr>");
                }
            }

            html.AppendLine("</table></body></html>");

            return html.ToString();
        }


        private static void StartHttpServer()
        {
            Task.Run(() =>
            {
                var listener = new HttpListener();
                listener.Prefixes.Add("http://localhost:8888/");
                listener.Start();
                Console.WriteLine("Local server started on http://localhost:8888");

                while (true)
                {
                    try
                    {
                        var context = listener.GetContext();
                        var request = context.Request;
                        var response = context.Response;

                        if (request.Url != null && request.Url.AbsolutePath.StartsWith("/export/pdf"))
                        {
                            var pdfBytes = GeneratePdf();
                            response.ContentType = "application/pdf";
                            response.AddHeader("Content-Disposition", "attachment; filename=scan-results.pdf");
                            response.OutputStream.Write(pdfBytes, 0, pdfBytes.Length);
                        }
                        else if (request.Url != null && request.Url.AbsolutePath.StartsWith("/export/excel"))
                        {
                            var csvBytes = GenerateCsv();
                            response.ContentType = "text/csv";
                            response.AddHeader("Content-Disposition", "attachment; filename=scan-results.csv");
                            response.OutputStream.Write(csvBytes, 0, csvBytes.Length);
                        }
                        else if (request.Url != null && request.Url.AbsolutePath.StartsWith("/export/text"))
                        {
                            var textBytes = GenerateText();
                            response.ContentType = "text/plain";
                            response.AddHeader("Content-Disposition", "attachment; filename=scan-results.txt");
                            response.OutputStream.Write(textBytes, 0, textBytes.Length);
                        }
                        else
                        {
                            string html = GenerateHtmlPageWithExports();
                            byte[] buffer = Encoding.UTF8.GetBytes(html);
                            response.ContentLength64 = buffer.Length;
                            response.ContentType = "text/html; charset=utf-8";
                            response.OutputStream.Write(buffer, 0, buffer.Length);
                        }

                        response.OutputStream.Close();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"HTTP server error: {ex.Message}");
                    }
                }
            });
        }

        private static byte[] GeneratePdf()
        {
            GlobalFontSettings.FontResolver = new CustomFontResolver();

            using var document = new PdfDocument();
            var page = document.AddPage();
            var gfx = XGraphics.FromPdfPage(page);
            
            var font = new XFont("Arial", 12);
            var boldFont = new XFont("Arial", 12, XFontStyleEx.Bold);
            var titleFont = new XFont("Arial", 16, XFontStyleEx.Bold);

            var y = 50.0;
            var lineHeight = 20.0;

            gfx.DrawString($"Port Scan Results for {scannedHost}", titleFont, XBrushes.Black, 50, y);
            y += lineHeight * 2;

            gfx.DrawString("Port", boldFont, XBrushes.Black, 50, y);
            gfx.DrawString("Status", boldFont, XBrushes.Black, 100, y);
            gfx.DrawString("Service", boldFont, XBrushes.Black, 200, y);
            y += lineHeight;

            foreach (var result in scanResults.Values.OrderBy(r => r.Port))
            {
                if (XUnit.FromPoint(y)
                    > page.Height - XUnit.FromPoint(50))
                {
                    page = document.AddPage();
                    gfx.Dispose();
                    gfx = XGraphics.FromPdfPage(page);
                    y = 50;
                }

                gfx.DrawString(result.Port.ToString(), font, XBrushes.Black, 50, y);
                gfx.DrawString(result.Status, font, XBrushes.Black, 100, y);
                gfx.DrawString(result.Service ?? "", font, XBrushes.Black, 200, y);
                y += lineHeight;
            }

            gfx.Dispose();
            using var ms = new MemoryStream();
            document.Save(ms);
            return ms.ToArray();
        }

        private static byte[] GenerateCsv()
        {
            var sb = new StringBuilder();
            sb.AppendLine("IP:Port,Status,Service");
            lock (scanResultsLock)
            {
                foreach (var r in scanResults.Values.OrderBy(r => r.Port))
                {
                    string service = r.Service?.Replace("\"", "\"\"") ?? "Unknown";
                    sb.AppendLine($"{scannedHost}:{r.Port},{r.Status},\"{service}\"");
                }
            }
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        private static byte[] GenerateText()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Advanced Port Scanner Report");
            sb.AppendLine("============================");
            sb.AppendLine($"Scanning Host: {scannedHost}");
            sb.AppendLine("----------------------------");
            lock (scanResultsLock)
            {
                foreach (var r in scanResults.Values.OrderBy(r => r.Port))
                {
                    sb.AppendLine($"IP:Port: {scannedHost}:{r.Port}");
                    sb.AppendLine($"Status: {r.Status}");
                    sb.AppendLine($"Service: {r.Service ?? "Unknown"}");
                    sb.AppendLine("----------------------------");
                }
            }
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        private static void OpenBrowser(string url)
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    Process.Start("xdg-open", url);
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    Process.Start("open", url);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to open browser: {ex.Message}");
            }
        }

        private static Dictionary<string, string> ParseArgs(string[] args)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < args.Length - 1; i += 2)
            {
                if (args[i].StartsWith("--"))
                    dict[args[i].TrimStart('-')] = args[i + 1];
            }
            return dict;
        }

        private static string? GetArg(Dictionary<string, string> args, string key) =>
            args.TryGetValue(key, out var value) ? value : null;

        private static string Prompt(string message)
        {
            Console.Write(message + " ");
            return Console.ReadLine() ?? string.Empty;
        }

        private static string GetMinThreadPool()
        {
            ThreadPool.GetMinThreads(out int workerThreads, out int ioThreads);
            return $"{workerThreads} worker, {ioThreads} I/O";
        }

        public record PortScanResult(int Port, string Status, string? Service);
    }
}
