using System;
using System.Diagnostics;
using System.IO;

namespace Sora.Ancient
{
    // Owns the era engine process. Errors surfaced to the UI are named,
    // short states ("engine missing", "engine exited early") — the raw
    // engine log stays in a file next to the config, never in a dialog.
    internal sealed class EngineRunner : IDisposable
    {
        private Process _process;

        public static string FindEngine(string baseDir)
        {
            string[] candidates =
            {
                Path.Combine(baseDir, "engine", "v2ray.exe"),
                Path.Combine(baseDir, "v2ray.exe"),
                Path.Combine(baseDir, "engines", "windows-32", "v2ray-v3.36-windows-32", "v2ray.exe"),
                Path.Combine(baseDir, "engines", "windows-64", "v2ray-v3.36-windows-64", "v2ray.exe")
            };
            foreach (string c in candidates) if (File.Exists(c)) return c;
            return null;
        }

        public void Start(string enginePath, string configPath)
        {
            Stop();
            if (enginePath == null || !File.Exists(enginePath))
                throw new InvalidOperationException("Era engine (v2ray.exe) not found. Stage it with stage-engines.sh / stage-engines.ps1 first.");
            var psi = new ProcessStartInfo();
            psi.FileName = enginePath;
            psi.Arguments = "-config " + Quote(configPath);
            psi.WorkingDirectory = Path.GetDirectoryName(enginePath);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            try { _process = Process.Start(psi); }
            catch (Exception) { throw new InvalidOperationException("Era engine failed to start."); }
            if (_process == null) throw new InvalidOperationException("Era engine failed to start.");
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
            System.Threading.Thread.Sleep(600);
            if (_process.HasExited)
            {
                int code = _process.ExitCode;
                _process = null;
                throw new InvalidOperationException("Era engine exited immediately (code " + code + "). Check config and engine log.");
            }
        }

        public void Stop()
        {
            try
            {
                if (_process != null && !_process.HasExited)
                {
                    _process.Kill();
                    _process.WaitForExit(3000);
                }
            }
            catch (InvalidOperationException) { /* already exited */ }
            finally
            {
                if (_process != null) { _process.Dispose(); _process = null; }
            }
        }

        public void Dispose() { Stop(); }

        private static string Quote(string path)
        {
            return "\"" + path.Replace("\"", "") + "\"";
        }
    }
}
