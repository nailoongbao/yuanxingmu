using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Yuanxingmu.WindowsLauncher
{
    internal static class Product
    {
        internal const string Version = "0.1.0a1";
        internal const int DefaultPort = 18910;
#if DEV_BUILD
        internal const bool Development = true;
#else
        internal const bool Development = false;
#endif
    }

    internal static class Arguments
    {
        // Windows CreateProcess/CommandLineToArgvW quoting, without cmd.exe.
        internal static string Quote(string value)
        {
            if (value == null || value.IndexOf('\0') >= 0) throw new ArgumentException("Invalid argument");
            // wsl.exe parses its own fixed switches before the Linux argv layer.
            // Keep ordinary arguments unquoted, as standard Windows encoders do.
            bool needed = value.Length == 0;
            foreach (char c in value) if (Char.IsWhiteSpace(c) || c == '"') needed = true;
            if (!needed) return value;
            StringBuilder result = new StringBuilder("\"");
            int slashes = 0;
            foreach (char c in value)
            {
                if (c == '\\') { slashes++; continue; }
                result.Append('\\', c == '"' ? slashes * 2 + 1 : slashes);
                result.Append(c);
                slashes = 0;
            }
            result.Append('\\', slashes * 2);
            return result.Append('"').ToString();
        }

        internal static string Join(IEnumerable<string> values)
        {
            List<string> quoted = new List<string>();
            foreach (string value in values) quoted.Add(Quote(value));
            string result = String.Join(" ", quoted.ToArray());
            if (result.Length > 30000) throw new ArgumentException("Command line too long");
            return result;
        }

        internal static bool Plain(string value, int maximum)
        {
            if (String.IsNullOrEmpty(value) || value.Length > maximum) return false;
            foreach (char c in value) if (Char.IsControl(c)) return false;
            return true;
        }

        internal static bool Distribution(string value)
        {
            return Plain(value, 256) && value[0] != '-';
        }

        internal static bool LinuxPath(string value)
        {
            if (!Plain(value, 1024) || !value.StartsWith("/", StringComparison.Ordinal)
                || value.EndsWith("/", StringComparison.Ordinal)) return false;
            foreach (string part in value.Substring(1).Split('/'))
                if (part.Length == 0 || part == "." || part == "..") return false;
            return true;
        }

        internal static bool Port(int port) { return port >= 1024 && port <= 65535 && port != 18701; }
    }

    internal static class ReadyAddress
    {
        internal static bool Valid(string value, int port)
        {
            return Arguments.Port(port) && value != null && Regex.IsMatch(value,
                @"\Ahttp://127\.0\.0\.1:" + port.ToString(CultureInfo.InvariantCulture)
                + @"/#access=[A-Za-z0-9_-]{32,128}\z", RegexOptions.CultureInvariant);
        }
    }

    // Small bounded JSON reader for the bridge's protocol. Duplicate keys,
    // floating point numbers and trailing content are rejected explicitly.
    internal sealed class WireJson
    {
        private readonly string source;
        private int position;
        private WireJson(string value) { source = value; }

        internal static object Parse(string value)
        {
            if (value == null || value.Length > 16384) throw new InvalidDataException();
            WireJson parser = new WireJson(value);
            object result = parser.Value(0);
            parser.Space();
            if (parser.position != value.Length) throw new InvalidDataException();
            return result;
        }

        private void Space()
        {
            while (position < source.Length && (source[position] == ' ' || source[position] == '\t'
                || source[position] == '\r' || source[position] == '\n')) position++;
        }

        private bool Take(char c)
        {
            Space();
            if (position >= source.Length || source[position] != c) return false;
            position++; return true;
        }

        private object Value(int depth)
        {
            Space();
            if (depth > 6 || position == source.Length) throw new InvalidDataException();
            char c = source[position];
            if (c == '"') return Text();
            if (Take('{'))
            {
                Dictionary<string, object> result = new Dictionary<string, object>(StringComparer.Ordinal);
                if (Take('}')) return result;
                do
                {
                    string key = Text();
                    if (!Take(':') || result.ContainsKey(key) || result.Count >= 16) throw new InvalidDataException();
                    result.Add(key, Value(depth + 1));
                    if (Take('}')) return result;
                } while (Take(','));
                throw new InvalidDataException();
            }
            if (Take('['))
            {
                List<object> result = new List<object>();
                if (Take(']')) return result;
                do
                {
                    if (result.Count >= 16) throw new InvalidDataException();
                    result.Add(Value(depth + 1));
                    if (Take(']')) return result;
                } while (Take(','));
                throw new InvalidDataException();
            }
            if (c == '-' || (c >= '0' && c <= '9'))
            {
                int start = position;
                if (c == '-') position++;
                int digits = position;
                while (position < source.Length && source[position] >= '0' && source[position] <= '9') position++;
                if (digits == position || (position - digits > 1 && source[digits] == '0')) throw new InvalidDataException();
                int number;
                if (!Int32.TryParse(source.Substring(start, position - start), NumberStyles.AllowLeadingSign,
                    CultureInfo.InvariantCulture, out number)) throw new InvalidDataException();
                return number;
            }
            throw new InvalidDataException();
        }

        private string Text()
        {
            if (!Take('"')) throw new InvalidDataException();
            StringBuilder result = new StringBuilder();
            bool closed = false;
            while (position < source.Length)
            {
                char c = source[position++];
                if (c == '"') { closed = true; break; }
                if (c < 32) throw new InvalidDataException();
                if (c == '\\')
                {
                    if (position == source.Length) throw new InvalidDataException();
                    c = source[position++];
                    if (c == 'u')
                    {
                        if (position + 4 > source.Length) throw new InvalidDataException();
                        ushort code;
                        if (!UInt16.TryParse(source.Substring(position, 4), NumberStyles.HexNumber,
                            CultureInfo.InvariantCulture, out code)) throw new InvalidDataException();
                        result.Append((char)code); position += 4; continue;
                    }
                    switch (c)
                    {
                        case '"': case '\\': case '/': break;
                        case 'b': c = '\b'; break;
                        case 'f': c = '\f'; break;
                        case 'n': c = '\n'; break;
                        case 'r': c = '\r'; break;
                        case 't': c = '\t'; break;
                        default: throw new InvalidDataException();
                    }
                }
                result.Append(c);
            }
            if (!closed) throw new InvalidDataException();
            string text = result.ToString();
            for (int i = 0; i < text.Length; i++)
                if (Char.IsSurrogate(text[i]))
                {
                    if (!Char.IsHighSurrogate(text[i]) || i + 1 == text.Length || !Char.IsLowSurrogate(text[++i]))
                        throw new InvalidDataException();
                }
            return text;
        }
    }

    internal sealed class BridgeEvent
    {
        internal string Kind;
        internal string Url;
        internal string Code;
        internal string Home;
        internal List<string> Candidates;
        internal int ExitCode;

        private static void Keys(Dictionary<string, object> value, params string[] keys)
        {
            if (value == null || value.Count != keys.Length) throw new InvalidDataException();
            foreach (string key in keys) if (!value.ContainsKey(key)) throw new InvalidDataException();
        }

        private static string StringValue(Dictionary<string, object> value, string key, int maximum)
        {
            object item;
            if (!value.TryGetValue(key, out item) || !(item is string)
                || ((string)item).Length > maximum) throw new InvalidDataException();
            return (string)item;
        }

        internal static BridgeEvent Parse(string line, int port)
        {
            Dictionary<string, object> value = WireJson.Parse(line) as Dictionary<string, object>;
            if (value == null) throw new InvalidDataException();
            BridgeEvent result = new BridgeEvent();
            result.Kind = StringValue(value, "event", 32);
            switch (result.Kind)
            {
                case "ready":
                    Keys(value, "event", "url");
                    result.Url = StringValue(value, "url", 200);
                    if (!ReadyAddress.Valid(result.Url, port)) throw new InvalidDataException();
                    break;
                case "error":
                    Keys(value, "event", "code", "message");
                    result.Code = StringValue(value, "code", 64);
                    if (!Regex.IsMatch(result.Code, @"\A[a-z][a-z0-9_]{0,63}\z")) throw new InvalidDataException();
                    StringValue(value, "message", 512); // Never displayed or logged; UI maps fixed codes.
                    break;
                case "status":
                    Keys(value, "event", "message");
                    StringValue(value, "message", 512);
                    break;
                case "stopped":
                    Keys(value, "event", "exit_code");
                    if (!(value["exit_code"] is int)) throw new InvalidDataException();
                    result.ExitCode = (int)value["exit_code"];
                    if (result.ExitCode < -255 || result.ExitCode > 255) throw new InvalidDataException();
                    break;
                case "probe":
                    Keys(value, "event", "home", "candidates");
                    result.Home = StringValue(value, "home", 1024);
                    if (!Arguments.LinuxPath(result.Home)) throw new InvalidDataException();
                    List<object> candidates = value["candidates"] as List<object>;
                    if (candidates == null || candidates.Count > 2) throw new InvalidDataException();
                    result.Candidates = new List<string>();
                    foreach (object item in candidates)
                    {
                        Dictionary<string, object> candidate = item as Dictionary<string, object>;
                        Keys(candidate, "root", "label");
                        string root = StringValue(candidate, "root", 1024);
                        StringValue(candidate, "label", 128);
                        if (!Arguments.LinuxPath(root) || !root.StartsWith(result.Home + "/", StringComparison.Ordinal)
                            || result.Candidates.Contains(root)) throw new InvalidDataException();
                        result.Candidates.Add(root);
                    }
                    break;
                default: throw new InvalidDataException();
            }
            return result;
        }
    }

    internal static class Wsl
    {
        internal static string Executable { get { return Path.Combine(Environment.SystemDirectory, "wsl.exe"); } }

        internal static ProcessStartInfo StartInfo(string executable, IEnumerable<string> arguments)
        {
            ProcessStartInfo info = new ProcessStartInfo(executable, Arguments.Join(arguments));
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.WindowStyle = ProcessWindowStyle.Hidden;
            info.RedirectStandardInput = true;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;
            info.WorkingDirectory = Environment.SystemDirectory;
            return info;
        }

        internal static List<string> DecodeDistributions(byte[] bytes)
        {
            if (bytes == null || bytes.Length > 65536) throw new InvalidDataException();
            bool wide = bytes.Length >= 2 && (bytes[0] == 255 && bytes[1] == 254);
            for (int i = 1; i < bytes.Length && !wide; i += 2) if (bytes[i] == 0) wide = true;
            string text = (wide ? (Encoding)new UnicodeEncoding(false, false, true)
                : new UTF8Encoding(false, true)).GetString(bytes).TrimStart('\ufeff');
            List<string> names = new List<string>();
            foreach (string raw in text.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string name = raw.Trim();
                if (!Arguments.Distribution(name) || names.Contains(name) || names.Count >= 64) throw new InvalidDataException();
                names.Add(name);
            }
            return names;
        }

        internal static List<string> ListDistributions()
        {
            if (!File.Exists(Executable)) throw new InvalidOperationException("wsl_missing");
            using (Process process = new Process())
            {
                process.StartInfo = StartInfo(Executable, new string[] { "--list", "--quiet" });
                process.Start(); process.StandardInput.Close();
                byte[] output = null;
                Exception failure = null;
                Thread reader = new Thread(delegate()
                {
                    try
                    {
                        using (MemoryStream buffer = new MemoryStream())
                        {
                            byte[] chunk = new byte[4096]; int count;
                            while ((count = process.StandardOutput.BaseStream.Read(chunk, 0, chunk.Length)) > 0)
                            {
                                if (buffer.Length + count > 65536) throw new InvalidDataException();
                                buffer.Write(chunk, 0, count);
                            }
                            output = buffer.ToArray();
                        }
                    }
                    catch (Exception error) { failure = error; }
                });
                Thread errors = new Thread(delegate() { DrainBytes(process.StandardError.BaseStream); });
                reader.IsBackground = errors.IsBackground = true;
                reader.Start(); errors.Start();
                if (!process.WaitForExit(15000))
                {
                    // This command only lists registrations; no Linux process was started.
                    try { process.Kill(); } catch (InvalidOperationException) { }
                    process.WaitForExit(5000);
                    throw new InvalidOperationException("wsl_list_failed");
                }
                reader.Join(5000); errors.Join(5000);
                if (failure != null || output == null || process.ExitCode != 0) throw new InvalidOperationException("wsl_list_failed");
                return DecodeDistributions(output);
            }
        }

        internal static void DrainBytes(Stream stream)
        {
            // A StreamReader may remain poisoned after a decoder failure. Drain
            // the pipe itself so an invalid UTF-8 writer cannot block cleanup.
            try { byte[] chunk = new byte[4096]; while (stream.Read(chunk, 0, chunk.Length) > 0) { } }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
        }

        internal static string BridgeBootstrap()
        {
            using (Stream resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("Yuanxingmu.Windows.Bridge"))
            {
                if (resource == null) throw new InvalidOperationException("bridge_missing");
                using (MemoryStream compressed = new MemoryStream())
                {
                    using (GZipStream gzip = new GZipStream(compressed, CompressionMode.Compress, true))
                        resource.CopyTo(gzip);
                    return "import base64,gzip;exec(compile(gzip.decompress(base64.b64decode('"
                        + Convert.ToBase64String(compressed.ToArray()) + "')),'<yuanxingmu-windows-bridge>','exec'))";
                }
            }
        }
    }

    internal sealed class SessionResult
    {
        internal bool Clean;
        internal string ErrorCode;
    }

    internal sealed class BridgeSession
    {
        private readonly string distribution, mode, root;
        private readonly int port;
        private readonly Action<BridgeEvent> received;
        private readonly Action<SessionResult> finished;
        private readonly object gate = new object();
        private Process process;
        private bool stopRequested;
        private bool stopSent;

        internal BridgeSession(string selectedDistribution, string selectedMode, string installRoot, int selectedPort,
            Action<BridgeEvent> onEvent, Action<SessionResult> onFinished)
        {
            if (!Arguments.Distribution(selectedDistribution) || (selectedMode != "probe" && selectedMode != "start")
                || !Arguments.Port(selectedPort) || (selectedMode == "start" && !Arguments.LinuxPath(installRoot)))
                throw new ArgumentException("Invalid launch selection");
            distribution = selectedDistribution; mode = selectedMode; root = installRoot; port = selectedPort;
            received = onEvent; finished = onFinished;
        }

        internal void Start()
        {
            Thread thread = new Thread(Run); thread.IsBackground = true; thread.Start();
        }

        internal void Stop()
        {
            lock (gate)
            {
                stopRequested = true;
                SendStop();
            }
        }

        private void SendStop()
        {
            if (process == null || stopSent) return;
            stopSent = true;
            try { process.StandardInput.WriteLine("{\"command\":\"stop\"}"); process.StandardInput.Flush(); }
            catch (IOException) { }
            catch (InvalidOperationException) { }
            finally { try { process.StandardInput.Close(); } catch (IOException) { } catch (InvalidOperationException) { } }
        }

        private static string Line(TextReader reader)
        {
            StringBuilder line = new StringBuilder(); int value;
            while ((value = reader.Read()) >= 0)
            {
                if (value == '\n') return line.ToString().TrimEnd('\r');
                if (line.Length >= 16384) throw new InvalidDataException();
                line.Append((char)value);
            }
            if (line.Length > 0) throw new InvalidDataException();
            return null;
        }

        private void Run()
        {
            SessionResult result = new SessionResult();
            bool stopped = false, ready = false, probed = false, failed = false;
            int stoppedCode = -1;
            Thread errors = null;
            try
            {
                List<string> args = new List<string>(new string[] { "--distribution", distribution, "--exec",
                    "/usr/bin/python3", "-I", "-B", "-c", Wsl.BridgeBootstrap(), mode });
                if (mode == "start") { args.Add(root); args.Add(port.ToString(CultureInfo.InvariantCulture)); }
                Process child = new Process();
                child.StartInfo = Wsl.StartInfo(Wsl.Executable, args);
                child.StartInfo.StandardOutputEncoding = new UTF8Encoding(false, true);
                child.StartInfo.StandardErrorEncoding = new UTF8Encoding(false, false);
                child.Start();
                lock (gate) { process = child; if (stopRequested) SendStop(); }
                errors = new Thread(delegate() { Wsl.DrainBytes(child.StandardError.BaseStream); });
                errors.IsBackground = true; errors.Start();
                try
                {
                    string line;
                    while ((line = Line(child.StandardOutput)) != null)
                    {
                        BridgeEvent item = BridgeEvent.Parse(line, port);
                        if (stopped) throw new InvalidDataException();
                        switch (item.Kind)
                        {
                            case "ready":
                                if (mode != "start" || ready || failed) throw new InvalidDataException();
                                ready = true; break;
                            case "probe":
                                if (mode != "probe" || probed || failed) throw new InvalidDataException();
                                probed = true; break;
                            case "error": failed = true; result.ErrorCode = item.Code; break;
                            case "stopped": stopped = true; stoppedCode = item.ExitCode; break;
                        }
                        received(item);
                    }
                }
                catch (Exception error)
                {
                    if (!(error is IOException) && !(error is DecoderFallbackException) && !(error is ArgumentException)) throw;
                    result.ErrorCode = "protocol_error"; failed = true; Stop();
                    Wsl.DrainBytes(child.StandardOutput.BaseStream);
                }
                // No timeout/kill: the bridge waits for accepted operations to finish.
                child.WaitForExit();
                errors.Join();
                result.Clean = !failed && stopped && stoppedCode == 0 && child.ExitCode == 0
                    && (mode == "probe" ? probed : (ready || stopRequested));
                if (!result.Clean && result.ErrorCode == null) result.ErrorCode = "bridge_stopped_unexpectedly";
            }
            catch (Exception)
            {
                result.ErrorCode = "bridge_start_failed";
                Stop();
                Process child;
                lock (gate) { child = process; }
                if (child != null)
                {
                    Wsl.DrainBytes(child.StandardOutput.BaseStream);
                    try { child.WaitForExit(); } catch (InvalidOperationException) { }
                    if (errors != null) errors.Join();
                }
            }
            finally
            {
                lock (gate) { if (process != null) { process.Dispose(); process = null; } }
                finished(result);
            }
        }
    }
}
