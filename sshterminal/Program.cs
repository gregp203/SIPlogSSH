using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Renci.SshNet;
using System.Threading;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace sshterminal
{
    class Program
    {
        ShellStream shellStream;
        StreamReader sread;
        Queue<String> fifo = new Queue<string>();
       
        

        static void Main(string[] args)
        {
            Program ProragmObj = new Program();
            ProragmObj.sshterm();

        }           

        void sshterm()
        {
            

            PasswordAuthenticationMethod pauth = new PasswordAuthenticationMethod("root", @"Mr\6(atn2).F");
            ConnectionInfo connectionInfo = new ConnectionInfo("192.168.197.100", 22, "root", pauth);
            SshClient client = new SshClient(connectionInfo);
            client.Connect();
            string reply = string.Empty;
            shellStream = client.CreateShellStream("dumb", 80, 24, 800, 600, 1024);
            sread = new StreamReader(shellStream);            
            shellStream.DataReceived += DataReceivedEventHandler;
            Console.CancelKeyPress += CtlCEventHandler;
            ConsoleKeyInfo keyInfo;
            String output;
            
            while (client.IsConnected)
            {
                keyInfo = Console.ReadKey(true);
                 
                output = keyInfo.KeyChar.ToString();
                if (keyInfo.Modifiers == ConsoleModifiers.Control && keyInfo.Key==ConsoleKey.T)
                {  }
                shellStream.Write(output);
            }
        }

        private void DataReceivedEventHandler(object sender, Renci.SshNet.Common.ShellDataEventArgs e)
        {
            
            while (shellStream.DataAvailable || fifo.Count > 0)
            {
                string sshdata;
                sshdata = sread.ReadToEnd();
                String output = "";
                String line = "";
                if (!String.IsNullOrEmpty(sshdata))
                {
                    
                    Console.Write(sshdata);

                    char[] c = sshdata.ToCharArray();
                    sshdata = "";
                    for (int i = 0; i < c.Length; i++)
                    {
                        if (c[i] == '\r') { i++; }
                        if (c[i] =='\n')
                        {
                            fifo.Enqueue(line);
                            line = "";
                        }
                        else
                        {
                            line = line + c[i];
                        }
                    }
                }
                if(fifo.Count > 0)
                {
                    output = fifo.Dequeue();
                }

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(output);
                Console.ForegroundColor = ConsoleColor.Gray;
            }

        }
        private void CtlCEventHandler(object sender, ConsoleCancelEventArgs args)
        {
            shellStream.Write("\x03");
        }
    }
}
