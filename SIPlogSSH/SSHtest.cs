using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Renci.SshNet;

/*namespace SIPlogSSH
{
    class SSHtest
    {
        static void Main()
        {
            using (var client = new SshClient("10.204.131.32", "shelldiag", "fdpch?K2p7"))
            {
                client.Connect();
                var command = "tail -f /var/opt/ipc/log/sip_messages/sip_messages.log";
                var cmd = client.CreateCommand(command);
                var result = cmd.BeginExecute();
                using (var reader = new StreamReader(cmd.OutputStream))
                {
                    while (!result.IsCompleted || !reader.EndOfStream)
                    {
                        string line = reader.ReadLine();
                        if (line != null)
                        {
                            Console.WriteLine(line);
                        }
                    }
                }
                cmd.EndExecute(result);
            }
        }
    }
}
*/