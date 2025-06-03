// Project: AdvancedPortScanner
// File: Program.cs

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AdvancedPortScanner
{
    internal class Program
    {
        private static readonly List<PortScanResult> scanResults = new();
        private static readonly SemaphoreSlim semaphore = new(100); // Limit to 100 concurrent scans

        private static async Task Main(string[] args)
        {
            var parsedArgs = ParseArgs(args);

            string? host = GetArg(parsedArgs, "host") ?? Prompt("🌐 Enter host to scan:");
            int startingPort = int.TryParse(GetArg(parsedArgs, "start"), out var s) ? s : int.Parse(Prompt("🔢 Starting port:"));
            int endingPort = int.TryParse(GetArg(parsedArgs, "end"), out var e) ? e : int.Parse(Prompt("🔢 Ending port:"));

            Console.WriteLine($"🧠 Logical processors: {Environment.ProcessorCount}");
            Console.WriteLine($"🔧 ThreadPool min threads: {GetMinThreadPool()}");

            var stopwatch = Stopwatch.StartNew();
            await TraditionalPortScanner(host, startingPort, endingPort);
            stopwatch.Stop();

            await SaveResultsAsync();
            Console.WriteLine($"\n⏱️ Scan completed in {stopwatch.ElapsedMilliseconds} ms");
        }

        private static async Task TraditionalPortScanner(string host, int startingPort, int endingPort)
        {
            List<Task> scanTasks = new();
            for (int port = startingPort; port <= endingPort; port++)
            {
                scanTasks.Add(ScanPortAsync(host, port));
            }
            await Task.WhenAll(scanTasks);
        }

        private static async Task ScanPortAsync(string host, int port)
        {
            int taskId = Task.CurrentId ?? -1;
            int threadId = Thread.CurrentThread.ManagedThreadId;

            await semaphore.WaitAsync();
            try
            {
                using var client = new TcpClient();
                using var cts = new CancellationTokenSource(1000);
                await client.ConnectAsync(host, port, cts.Token);

                string? banner = null;
                if (client.Connected)
                {
                    using var stream = client.GetStream();
                    banner = await GrabBannerAsync(stream);
                }

                Console.WriteLine($"[Task:{taskId} Thread:{threadId}] ✅ Port {port} is OPEN");
                if (!string.IsNullOrWhiteSpace(banner))
                    Console.WriteLine($"[Task:{taskId}] 🏷️ Banner: {banner}");

                lock (scanResults)
                {
                    scanResults.Add(new PortScanResult(port, "Open", banner));
                }
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine($"[Task:{taskId} Thread:{threadId}] ⏳ Port {port} timeout/filtered");
                lock (scanResults) { scanResults.Add(new PortScanResult(port, "Timeout", null)); }
            }
            catch (SocketException)
            {
                Console.WriteLine($"[Task:{taskId} Thread:{threadId}] ❌ Port {port} is CLOSED");
                lock (scanResults) { scanResults.Add(new PortScanResult(port, "Closed", null)); }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Task:{taskId} Thread:{threadId}] ⚠️ Error on port {port}: {ex.Message}");
                lock (scanResults) { scanResults.Add(new PortScanResult(port, "Error", ex.Message)); }
            }
            finally
            {
                semaphore.Release();
            }
        }

        private static async Task<string?> GrabBannerAsync(NetworkStream stream)
        {
            byte[] buffer = new byte[256];
            try
            {
                using var cts = new CancellationTokenSource(1000);
                var readTask = stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cts.Token);
                int bytesRead = await readTask;
                return bytesRead > 0 ? Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim() : null;
            }
            catch
            {
                return null;
            }
        }

        private static async Task SaveResultsAsync()
        {
            var lines = scanResults.Select(r => $"Port {r.Port}: {r.Status} {(string.IsNullOrWhiteSpace(r.Banner) ? "" : $"- {r.Banner}")}");
            await File.WriteAllLinesAsync("scan-results.txt", lines);

            var json = JsonSerializer.Serialize(scanResults, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync("scan-results.json", json);

            Console.WriteLine("📄 Scan results saved to scan-results.txt and scan-results.json");
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

        public record PortScanResult(int Port, string Status, string? Banner);
    }
}
// This code is a simple port scanner that scans a range of ports on a specified host.