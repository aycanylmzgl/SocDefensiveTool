using System;
using System.Diagnostics;

namespace SocDefensiveTool
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "SOC Defensive Tool - Threat Hunter";
            Console.WriteLine("[*] SOC Defensive Tool - Windows Event Log Hunter Started...");
            Console.WriteLine("[*] Listening for failed logon attempts (Event ID: 4625)...\n");

            try
            {
                // Connect to the Windows "Security" event log
                EventLog securityLog = new EventLog("Security");

                // Enable the application to trigger an event when a new log is written
                securityLog.EnableRaisingEvents = true;

                // Route the new log entry to our custom analysis function
                securityLog.EntryWritten += new EntryWrittenEventHandler(AnalyzeLogEntry);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Successfully connected to the Security Event Log.");
                Console.WriteLine("[+] Monitoring in real-time. Press 'Enter' to exit.\n");
                Console.ResetColor();

                Console.ReadLine(); // Keep the console open
            }
            catch (UnauthorizedAccessException)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] ERROR: Access Denied.");
                Console.WriteLine("[-] Please restart Visual Studio as Administrator to read Security logs.");
                Console.ResetColor();
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] An unexpected error occurred: {ex.Message}");
                Console.ReadLine();
            }
        }

        // This function is triggered automatically EVERY TIME a new log is written to Windows
        private static void AnalyzeLogEntry(object source, EntryWrittenEventArgs e)
        {
            // Check if the new log is a Failed Logon attempt (Event ID 4625)
            if (e.Entry.InstanceId == 4625)
            {
                // Extracting raw data from Windows Event parameters (ReplacementStrings)
                // Index 5 is TargetUserName, Index 19 is IpAddress for Event ID 4625
                string targetUser = e.Entry.ReplacementStrings.Length > 5 ? e.Entry.ReplacementStrings[5] : "Unknown";
                string ipAddress = e.Entry.ReplacementStrings.Length > 19 ? e.Entry.ReplacementStrings[19] : "Unknown";

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ALERT] Brute Force / Failed Logon Detected!");
                Console.WriteLine($"Time           : {e.Entry.TimeGenerated}");
                Console.WriteLine($"Target User    : {targetUser}");
                Console.WriteLine($"Source IP      : {ipAddress}");
                Console.WriteLine(new string('-', 60));
                Console.ResetColor();
            }
        }
    }
}