using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Web.Script.Serialization;
using Yuanxingmu.WindowsLauncher;

internal static class OfflineTests
{
    private static int passed;
    private static void Check(bool value, string name)
    {
        if (!value) throw new Exception("Failed: " + name);
        passed++; Console.WriteLine("PASS " + name);
    }

    private static void Reject(Action action, string name)
    {
        bool rejected = false;
        try { action(); } catch (Exception) { rejected = true; }
        Check(rejected, name);
    }

    private static int Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        if (args.Length > 0 && args[0] == "echo-args")
        {
            string[] values = new string[args.Length - 1]; Array.Copy(args, 1, values, 0, values.Length);
            Console.Write(new JavaScriptSerializer().Serialize(values)); return 0;
        }
        if (args.Length > 0 && args[0] == "bad-utf8")
        {
            byte[] invalid = new byte[100000];
            for (int i = 0; i < invalid.Length; i++) invalid[i] = 255;
            using (Stream output = Console.OpenStandardOutput()) { output.Write(invalid, 0, invalid.Length); output.Flush(); }
            return 0;
        }
        try
        {
            if (args.Length > 0 && args[0] == "check-wsl-list")
            {
                List<string> registered = Wsl.ListDistributions();
                Check(registered != null, "actual_readonly_wsl_listing");
                Console.WriteLine("Registered WSL distributions: " + registered.Count); return 0;
            }
            string[] cases = new string[] { "", "plain", "a b", "中文目录", "quote\"inside", "\\", "end\\\\",
                "C:\\spaces and \\", "x\\\\\"y", "$(write-file) ; & | %PATH% `x`", "\nstatic Python\ncode\n", "/home/u/a 'quote' $value" };
            List<string> invocation = new List<string>(); invocation.Add("echo-args"); invocation.AddRange(cases);
            using (Process child = new Process())
            {
                child.StartInfo = Wsl.StartInfo(Assembly.GetExecutingAssembly().Location, invocation);
                child.StartInfo.StandardOutputEncoding = new UTF8Encoding(false, true);
                child.Start(); child.StandardInput.Close();
                string raw = child.StandardOutput.ReadToEnd();
                child.StandardError.ReadToEnd(); child.WaitForExit();
                string[] decoded = new JavaScriptSerializer().Deserialize<string[]>(raw);
                Check(child.ExitCode == 0 && decoded.Length == cases.Length, "real_CreateProcess_argument_count");
                for (int i = 0; i < cases.Length; i++) Check(decoded[i] == cases[i], "real_CreateProcess_argument_" + i);
            }
            Reject(delegate { Arguments.Quote("x\0y"); }, "NUL_argument_rejected");
            Reject(delegate { Arguments.Join(new string[] { new string('x', 30001) }); }, "oversized_command_rejected");
            Check(Arguments.Join(new string[] { "--list", "--quiet" }) == "--list --quiet"
                && Arguments.Quote("--distribution") == "--distribution" && Arguments.Quote("--exec") == "--exec",
                "WSL_fixed_switches_keep_native_spelling");
            Check(Arguments.LinuxPath("/home/user/资料 $x 'quoted'") && !Arguments.LinuxPath("C:\\data")
                && !Arguments.LinuxPath("/home/u/../other") && !Arguments.LinuxPath("/home/u/line\nbreak"), "Linux_path_data_validation");
            Check(Arguments.LinuxPath("/home/user/install ") && Arguments.Quote("/home/user/install ") == "\"/home/user/install \"",
                "trailing_space_path_is_literal_data");
            Check(!Arguments.Port(18701) && !Arguments.Port(1023) && Arguments.Port(18910), "reserved_port_rejected");

            using (Process writer = new Process())
            {
                writer.StartInfo = Wsl.StartInfo(Assembly.GetExecutingAssembly().Location, new string[] { "bad-utf8" });
                writer.StartInfo.StandardOutputEncoding = new UTF8Encoding(false, true);
                writer.Start(); writer.StandardInput.Close();
                bool decoderFailed = false;
                try { writer.StandardOutput.Read(); } catch (DecoderFallbackException) { decoderFailed = true; }
                Wsl.DrainBytes(writer.StandardOutput.BaseStream);
                bool exited = writer.WaitForExit(5000);
                if (!exited) { writer.Kill(); writer.WaitForExit(); }
                Check(decoderFailed && exited && writer.ExitCode == 0, "invalid_UTF8_pipe_is_drained_until_writer_exits");
            }

            byte[] wide = Encoding.Unicode.GetBytes("\ufeffUbuntu-24.04\r\n测试发行版\r\n");
            List<string> names = Wsl.DecodeDistributions(wide);
            Check(names.Count == 2 && names[1] == "测试发行版", "UTF16_WSL_listing");
            Check(Wsl.DecodeDistributions(Encoding.UTF8.GetBytes("Ubuntu\n")).Count == 1, "UTF8_listing_supported");
            Check(Wsl.DecodeDistributions(Encoding.Unicode.GetBytes("\r\n")).Count == 0, "empty_WSL_listing");
            Reject(delegate { Wsl.DecodeDistributions(Encoding.Unicode.GetBytes("Ubuntu\nUbuntu\n")); }, "duplicate_distro_rejected");
            Reject(delegate { Wsl.DecodeDistributions(new byte[] { 255, 254, 65 }); }, "truncated_UTF16_rejected");
            Reject(delegate { Wsl.DecodeDistributions(Encoding.UTF8.GetBytes("--exec\n")); }, "option_name_distro_rejected");

            string token = new string('A', 32);
            string url = "http://127.0.0.1:18910/#access=" + token;
            Check(BridgeEvent.Parse("{\"event\":\"ready\",\"url\":\"" + url + "\"}", 18910).Url == url, "ready_url_accepted");
            string[] unsafeUrls = new string[] { url + "\n", url + "&x=1", url.Replace("127.0.0.1", "localhost"),
                url.Replace("127.0.0.1", "127.0.0.1.evil.test"), url.Replace("127.0.0.1", "user@127.0.0.1"),
                url.Replace("18910", "18911"), url.Replace("http:", "https:"), url.Replace("/#", "/other#"),
                url.Substring(0, url.Length - 1), "file:///C:/Windows", url + new string('B', 97) };
            for (int i = 0; i < unsafeUrls.Length; i++) Check(!ReadyAddress.Valid(unsafeUrls[i], 18910), "unsafe_URL_" + i);
            string[] badWire = new string[] {
                "{\"event\":\"status\",\"event\":\"status\",\"message\":\"x\"}",
                "{\"event\":\"status\",\"\\u0065vent\":\"status\",\"message\":\"x\"}",
                "{\"event\":\"status\",\"message\":\"x\",\"extra\":1}",
                "{\"event\":\"stopped\",\"exit_code\":0.0}",
                "{\"event\":\"stopped\",\"exit_code\":01}",
                "{\"event\":\"stopped\",\"exit_code\":0} trailing",
                "{\"event\":\"ready\",\"url\":\"http://evil.test/\"}",
                "{\"event\":\"probe\",\"home\":\"/home/u\",\"candidates\":[{\"root\":\"/home/other/install\",\"label\":\"a2\"}]}",
                "{\"event\":\"status\",\"message\":\"\\ud800\"}",
                new string('x', 16385)
            };
            for (int i = 0; i < badWire.Length; i++)
            {
                string raw = badWire[i]; Reject(delegate { BridgeEvent.Parse(raw, 18910); }, "invalid_protocol_" + i);
            }
            BridgeEvent probe = BridgeEvent.Parse("{\"event\":\"probe\",\"home\":\"/home/u\",\"candidates\":[{\"root\":\"/home/u/资料\",\"label\":\"a2\"}]}", 18910);
            Check(probe.Candidates.Count == 1, "bounded_candidate_protocol");
            Check(BridgeEvent.Parse("{\"event\":\"stopped\",\"exit_code\":-15}", 18910).ExitCode == -15, "nonclean_exit_preserved");
            Console.WriteLine("C# offline checks passed: " + passed); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error.GetType().Name + ": " + error.Message); return 1; }
    }
}
