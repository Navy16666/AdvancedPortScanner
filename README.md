# ⚡ Advanced Port Scanner (Async + Multithreaded)

A powerful, cross-platform asynchronous port scanner written in C#. Features include:

- ✅ Async scanning with `TcpClient`
- 🔁 Controlled concurrency using `SemaphoreSlim`
- 🏷️ Banner grabbing for open ports
- 💾 Export results to `.txt` and `.json`
- ⚙️ Command-line argument support

---

## 🚀 Usage

### Run with Prompts
```bash
dotnet run

## Example Usage
dotnet run -- --host example.com --start 20 --end 100
