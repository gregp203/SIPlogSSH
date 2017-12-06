using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Renci.SshNet;
using System.Threading;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class Siplogssh
{
    //tcpdump -i any -nn -A -tttt port 5060
    Regex beginmsg = new Regex(@"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{6}.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");  //regex to match the begining of the sip message (if it starts with a date and has time and two IP addresses) 
    string requestRgxStr = @"ACK.*SIP\/2\.0|BYE.*SIP\/2\.0|CANCEL.*SIP\/2\.0|INFO.*SIP\/2\.0|INVITE.*SIP\/2\.0|MESSAGE.*SIP\/2\.0|NOTIFY.*SIP\/2\.0|OPTIONS.*SIP\/2\.0|PRACK.*SIP\/2\.0|PUBLISH.*SIP\/2\.0|REFER.*SIP\/2\.0|REGISTER.*SIP\/2\.0|SUBSCRIBE.*SIP\/2\.0|UPDATE.*SIP\/2\.0|SIP\/2\.0 \d{3}.*";
    string callidRgxStr = @"(?<!-.{8})(?<=Call-ID:).*";
    string toRgxStr = @"(?<=To:).*";
    string fromRgxStr = @"(?<=From:).*";
    string uaRgxStr = @"(?<=User-Agent:).*";
    string serverRgxStr = @"(?<=Server:).*";
    string portRgxStr = @"(?<=m=audio )\d*";
    string codecRgxStr = @"(?<=RTP\/AVP )\d*";
    string SDPIPRgxStr = @"(?<=c=IN IP4 )(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})";
    string mAudioRgxStr = @"m=audio \d* RTP\/AVP \d*";
    string occasRgxStr = @"(?<=Contact: ).*wlssuser";
    Regex requestRgx;
    Regex callidRgx;
    Regex toRgx;
    Regex fromRgx;
    Regex uaRgx;
    Regex serverRgx;
    Regex portRgx;
    Regex codecRgx;
    Regex SDPIPRgx;
    Regex mAudioRgx;
    Regex occasRgx;
    enum CallLegColors { Green, Cyan, Red, Magenta, Yellow, DarkGreen, DarkCyan, DarkRed, DarkMagenta };
    enum AttrColor:short
    {
        Black, DarkBlue, DarkGreen, DarkCyan, DarkRed, DarkMagenta, Darkyellow, Gray, DarkGray, Blue, Green, Cyan, Red, Magenta, Yellow, White,       
    }
    List<string> streamData = new List<string>();
    List<string[]> messages = new List<string[]>();
    //  index start of msg[0] 
    //  date[1] 
    //  time[2]
    //  src IP[3]
    //  dst IP[4]
    //  first line of SIP msg[5] 
    //  Call-ID[6]
    //  To:[7]  
    //  From:[8]
    //  index end of msg[9]
    //  color [10]
    //  SDP [11]
    //  filename [12]
    //  SDP IP [13]
    //  SDP port [14]
    //  SDP codec [15]
    //  useragent or server[16]
    List<string[]> callLegs = new List<string[]>();
    //  date [0]
    //  time [1]
    //  To: [2]
    //  From: [3]
    //  Call-ID [4]
    //  selected [5]
    //  src ip [6]
    //  dst ip [7]
    //  filtered [8]
    //  notify [9]
    List<string[]> callLegsDisplayed = new List<string[]>();
    int CallInvites;
    int notifications;
    int registrations;
    int subscriptions;
    static readonly object _locker = new object();
    int callLegsDisplayedCountPrev;
    
    bool filterChange = false;
    string Server;
    int Port;
    string Username;
    bool DisplaySsh = true;
    bool TermChange = false;
    SshClient client;
    bool IsRunning = true;
    bool fileMode = false;
    long currentFileLoadLeng;
    long currentFileLoadProg;
    AttrColor statusBarTxtClr;
    AttrColor statusBarBkgrdClr;
    AttrColor headerTxtClr;
    AttrColor headerBkgrdClr;
    ConsoleColor fieldConsoleTxtClr;
    ConsoleColor fieldConsoleBkgrdClr;
    ConsoleColor fieldConsoleTxtInvrtClr;
    ConsoleColor fieldConsoleBkgrdInvrtClr;
    ConsoleColor fieldConsoleSelectClr;
    AttrColor fieldAttrTxtClr;
    AttrColor fieldAttrTxtInvrtClr;
    AttrColor fieldAttrBkgrdClr;
    AttrColor fieldAttrBkgrdInvrtClr;
    AttrColor fieldAttrSelectClr;
    AttrColor footerTxtClr;
    AttrColor footerBkgrdClr;
    int[] fakeCursor = new int[2];       
    int numSelectdIps;
    int flowWidth;

    static void Main(String[] arg)
    {
        try
        {
            Siplogssh sIPlogSSHObj = new Siplogssh();
            sIPlogSSHObj.requestRgx = new Regex(sIPlogSSHObj.requestRgxStr); //I probably should have made a constructor that did these
            sIPlogSSHObj.callidRgx = new Regex(sIPlogSSHObj.callidRgxStr);
            sIPlogSSHObj.toRgx = new Regex(sIPlogSSHObj.toRgxStr);
            sIPlogSSHObj.fromRgx = new Regex(sIPlogSSHObj.fromRgxStr);
            sIPlogSSHObj.uaRgx = new Regex(sIPlogSSHObj.uaRgxStr);
            sIPlogSSHObj.serverRgx = new Regex(sIPlogSSHObj.serverRgxStr);
            sIPlogSSHObj.portRgx = new Regex(sIPlogSSHObj.portRgxStr);
            sIPlogSSHObj.codecRgx = new Regex(sIPlogSSHObj.codecRgxStr);
            sIPlogSSHObj.SDPIPRgx = new Regex(sIPlogSSHObj.SDPIPRgxStr);
            sIPlogSSHObj.mAudioRgx = new Regex(sIPlogSSHObj.mAudioRgxStr);
            sIPlogSSHObj.occasRgx = new Regex(sIPlogSSHObj.occasRgxStr);
            if (Console.BufferWidth < 200) { Console.BufferWidth = 200; }
            
            sIPlogSSHObj.ClearConsole();
                 
            sIPlogSSHObj.statusBarTxtClr = AttrColor.White;
            sIPlogSSHObj.statusBarBkgrdClr = AttrColor.Black;
            sIPlogSSHObj.headerTxtClr = AttrColor.Gray;
            sIPlogSSHObj.headerBkgrdClr = AttrColor.DarkBlue;
            sIPlogSSHObj.fieldConsoleTxtClr = ConsoleColor.Gray;
            sIPlogSSHObj.fieldConsoleBkgrdClr = ConsoleColor.DarkBlue;
            sIPlogSSHObj.fieldConsoleSelectClr = ConsoleColor.Red;
            sIPlogSSHObj.fieldConsoleTxtInvrtClr = ConsoleColor.DarkBlue; 
            sIPlogSSHObj.fieldConsoleBkgrdInvrtClr = ConsoleColor.Gray; 
            sIPlogSSHObj.fieldAttrTxtClr = AttrColor.Gray;
            sIPlogSSHObj.fieldAttrTxtInvrtClr = AttrColor.DarkBlue;
            sIPlogSSHObj.fieldAttrBkgrdClr = AttrColor.DarkBlue;
            sIPlogSSHObj.fieldAttrBkgrdInvrtClr = AttrColor.Gray;
            sIPlogSSHObj.fieldAttrSelectClr = AttrColor.Red;
            sIPlogSSHObj.footerTxtClr = AttrColor.Gray;
            sIPlogSSHObj.footerBkgrdClr = AttrColor.DarkBlue;
            sIPlogSSHObj.fakeCursor[0] = 0;
            sIPlogSSHObj.fakeCursor[1] = 0;

            sIPlogSSHObj.WriteLineConsole("",sIPlogSSHObj.statusBarTxtClr, sIPlogSSHObj.statusBarBkgrdClr);
            sIPlogSSHObj.WriteLineConsole(@"     _____ _____ ____  _              _____ _____ _    _  ", sIPlogSSHObj.fieldAttrTxtClr, sIPlogSSHObj.fieldAttrBkgrdClr);
            sIPlogSSHObj.WriteLineConsole(@"    / ____|_   _| __ \| |            / ____/ ____| |  | | ", sIPlogSSHObj.fieldAttrTxtClr, sIPlogSSHObj.fieldAttrBkgrdClr);
            sIPlogSSHObj.WriteLineConsole(@"   | (___   | | | __) | | ___   __ _| (___| (___ | |__| | ", sIPlogSSHObj.fieldAttrTxtClr, sIPlogSSHObj.fieldAttrBkgrdClr);
            sIPlogSSHObj.WriteLineConsole(@"    \___ \  | | | ___/| |/ _ \ / _` |\___ \\___ \|  __  | ", sIPlogSSHObj.fieldAttrTxtClr, sIPlogSSHObj.fieldAttrBkgrdClr);
            sIPlogSSHObj.WriteLineConsole(@"    ____) |_| |_| |   | | (_) | (_| |____) |___) | |  | | ", sIPlogSSHObj.fieldAttrTxtClr, sIPlogSSHObj.fieldAttrBkgrdClr);
            sIPlogSSHObj.WriteLineConsole(@"   |_____/|_____|_|   |_|\___/ \__, |_____/_____/|_|  |_| ", sIPlogSSHObj.fieldAttrTxtClr, sIPlogSSHObj.fieldAttrBkgrdClr);
            sIPlogSSHObj.WriteLineConsole(@"                                __/ |                     ", sIPlogSSHObj.fieldAttrTxtClr, sIPlogSSHObj.fieldAttrBkgrdClr);
            sIPlogSSHObj.WriteLineConsole(@"                               |___/                      ", sIPlogSSHObj.fieldAttrTxtClr, sIPlogSSHObj.fieldAttrBkgrdClr);
            sIPlogSSHObj.WriteLineConsole(@"   Version 1                                   Greg Palmer", sIPlogSSHObj.fieldAttrTxtClr, sIPlogSSHObj.fieldAttrBkgrdClr);

            if (arg.Length == 0)
            {
                sIPlogSSHObj.DisplaySsh = true;
                sIPlogSSHObj.fileMode = false;
                Thread SSHtermThread = new Thread(() => { sIPlogSSHObj.SSHterm(); });
                SSHtermThread.Start();
                sIPlogSSHObj.CallSelect(sIPlogSSHObj.callLegs, sIPlogSSHObj.messages);
            }
            else
            {
                sIPlogSSHObj.DisplaySsh = false;
                sIPlogSSHObj.fileMode = true;
                Thread SIPlogThread = new Thread(() => { sIPlogSSHObj.FileReader(arg); });
                SIPlogThread.Start();
                sIPlogSSHObj.CallSelect(sIPlogSSHObj.callLegs, sIPlogSSHObj.messages);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("\nMessage ---\n{0}", ex.Message);
            Console.WriteLine(
                "\nHelpLink ---\n{0}", ex.HelpLink);
            Console.WriteLine("\nSource ---\n{0}", ex.Source);
            Console.WriteLine(
                "\nStackTrace ---\n{0}", ex.StackTrace);
            Console.WriteLine(
                "\nTargetSite ---\n{0}", ex.TargetSite);
        }
    }

    void TopLine(string line, short x)
    {
        string displayLine;
        if (line.Length > 1)
        {
            displayLine = line + new String(' ', Console.BufferWidth - line.Length);
        }
        else
        {
            displayLine = line;
        }
        ConsoleBuffer.SetAttribute(x, 0, line.Length, 15);
        ConsoleBuffer.WriteAt(x, 0, displayLine);
        
        
    }

    void WriteScreen(string line, short x,short y, AttrColor attr, AttrColor bkgrd)
    {
        //string displayLine = line + new String(' ', Console.BufferWidth - line.Length);
        ConsoleBuffer.SetAttribute(x, y, line.Length, (short)( attr  +  (short)( ((short)bkgrd) * 16) ) );
        ConsoleBuffer.WriteAt(x, y, line);
    }
    void WriteConsole(string line, AttrColor attr,AttrColor bkgrd)
    {
        WriteScreen(line, (short)fakeCursor[0], (short)fakeCursor[1], attr, bkgrd);
        fakeCursor[0] = fakeCursor[0] + line.Length;
    }
    void WriteLineConsole(string line, AttrColor attr, AttrColor bkgrd)
    {
        WriteConsole(line + new String(' ', Console.BufferWidth-line.Length)
            ,  attr, bkgrd);
        fakeCursor[1]++;
        fakeCursor[0] = 0;
    }
    void ClearConsole()
    {
        int[] prevFakeCursor = new int[2];
        prevFakeCursor = fakeCursor;
        fakeCursor[0] = 0;fakeCursor[1] = 0;
        for (int i = 0; i < Console.BufferHeight; i++)
        {
            WriteLineConsole("", fieldAttrTxtClr, fieldAttrBkgrdClr);
        }
        fakeCursor = prevFakeCursor;
    }
    void ClearConsoleNoTop()
    {
        int[] prevFakeCursor = new int[2];
        prevFakeCursor = fakeCursor;
        fakeCursor[0] = 0; fakeCursor[1] = 1;
        for (int i = 0; i < Console.BufferHeight; i++)
        {
            WriteLineConsole("", fieldAttrTxtClr, fieldAttrBkgrdClr);
        }
        fakeCursor = prevFakeCursor;
    }

    void SSHterm()
    {
        bool tryBannerAgain = true;
        bool tryConnectAgain = true;
        while (IsRunning)
        {
            while (tryBannerAgain)
            {
                Console.Write("Enter Host : ");
                Server = Console.ReadLine();
                string PortStr;
                do
                {
                    Console.Write("Enter Port : ");
                    PortStr = Console.ReadLine();
                } while (!Regex.IsMatch(PortStr, @"^\d+$"));
                Port = Int32.Parse(PortStr);
                Console.Write("Enter User Name : ");
                Username = Console.ReadLine();
                try //try to connect just to get banner
                {
                    KeyboardInteractiveAuthenticationMethod kauth = new KeyboardInteractiveAuthenticationMethod(Username);
                    ConnectionInfo connectionInfoBanner = new ConnectionInfo(Server, 22, Username, kauth);
                    connectionInfoBanner.AuthenticationBanner += (sender, e) => Console.WriteLine(e.BannerMessage);
                    SshClient clientBanner = new SshClient(connectionInfoBanner);
                    clientBanner.Connect();
                    tryBannerAgain = false;
                    clientBanner.Disconnect();
                }
                catch (Exception ex)
                {
                    if (ex.Message.Contains("No suitable authentication method found"))
                    {
                        tryBannerAgain = false;
                    }
                    else
                    {
                        tryBannerAgain = true;
                        Console.WriteLine(ex.Message);
                    }
                }
            }
            if (tryConnectAgain)
            {
                try
                {
                    Console.Write("Enter Password : ");
                    PasswordAuthenticationMethod pauth = new PasswordAuthenticationMethod(Username, Console.ReadLine());
                    ConnectionInfo connectionInfo = new ConnectionInfo(Server, 22, Username, pauth);
                    client = new SshClient(connectionInfo);
                    client.Connect();
                    tryConnectAgain = false;
                    string reply = string.Empty;
                    ShellStream shellStream = client.CreateShellStream("dumb", 80, 24, 800, 600, 1024);
                    reply = shellStream.Expect(new Regex(@":.*>#"), new TimeSpan(0, 0, 3));
                    StreamReader sread = new StreamReader(shellStream);
                    string readconsole;                    
                    do
                    {
                        while (!DisplaySsh || !Console.KeyAvailable)
                        {
                            ReadData(sread, "SSH stream");
                        }
                        readconsole = Console.ReadLine();
                        if (String.IsNullOrEmpty(readconsole)) { readconsole = "\n"; }
                        if (readconsole == "+++") { readconsole = "\x03"; }
                        if (readconsole == "@@@")
                        {
                            Console.SetCursorPosition(0, 0);
                            TermChange = true;
                            DisplaySsh = false;
                        }
                        else
                        {
                            shellStream.WriteLine(readconsole);
                        }
                    } while (client.IsConnected);
                    int currentXPosA = Console.CursorLeft;
                    int currentYPosA = Console.CursorTop;
                    ConsoleColor currentBackA = Console.BackgroundColor;
                    ConsoleColor currentForeA = Console.ForegroundColor;
                    Console.SetCursorPosition(0, 0);
                    Console.BackgroundColor = ConsoleColor.Black;
                    Console.ForegroundColor = ConsoleColor.White;
                    if (!client.IsConnected) { Console.WriteLine("Disconected"); }
                    Console.SetCursorPosition(currentXPosA, currentYPosA);
                    Console.BackgroundColor = currentBackA;
                    Console.ForegroundColor = currentForeA;
                }
                catch (Exception ex)
                {
                    int currentXPos = Console.CursorLeft;
                    int currentYPos = Console.CursorTop;
                    ConsoleColor currentBack = Console.BackgroundColor;
                    ConsoleColor currentFore = Console.ForegroundColor;
                    if (!DisplaySsh) { Console.SetCursorPosition(0, 0); }
                    Console.BackgroundColor = ConsoleColor.Black;
                    Console.ForegroundColor = ConsoleColor.White;
                    if (DisplaySsh) { Console.Write(ex.Message); }
                    if (!DisplaySsh)
                    {
                        Console.Write(ex.Message.Split('\n')[0]);
                        Console.SetCursorPosition(currentXPos, currentYPos);
                    }
                    Console.BackgroundColor = currentBack;
                    Console.ForegroundColor = currentFore;
                }
            }
            if (DisplaySsh)
            {
                Console.WriteLine("would you like to attempt to connect again? yes/no");
                if (Console.ReadLine().ToLower().Contains("y"))
                {
                    tryConnectAgain = true;
                    tryBannerAgain = true;
                }
                else
                {
                    Console.SetCursorPosition(0, 0);
                    TermChange = true;
                    DisplaySsh = false;                    
                }
            }
        }
    }   

    void FileReader(string[] filenames)
    {
        foreach (string file in filenames)
        {
            currentFileLoadLeng = 0;
            currentFileLoadProg = 0;
            short x = 0;
            //count the number of lines in a file
            using (StreamReader sr = new StreamReader(file))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    currentFileLoadLeng++;                    
                    if (currentFileLoadLeng % 20000 == 0)
                    {
                        x = (short)(currentFileLoadLeng / 20000);
                        TopLine(".", (short)(x-1));
                    }
                }
                sr.Close();
                TopLine(" Reading " + currentFileLoadLeng + " lines of File : " + file, (short)(x));
            }
            Console.SetCursorPosition(0, 0);
            using (StreamReader sread = new StreamReader(file))
            {
                while (!sread.EndOfStream)
                {
                    ReadData(sread,file);
                }
                sread.Close();
            }
        }
        TopLine("Done reading all files "+ string.Join(" ", filenames), 0);
    }

    void ReadData(StreamReader sread,string fileName)
    {
        string line;
        if (!String.IsNullOrEmpty(line = sread.ReadLine()))
        {
            lock (_locker)
            {
                if (fileMode) { UpdateFileLoadProgress(); }
                else
                { streamData.Add(line); }
            }
            if (!fileMode && DisplaySsh) { Console.WriteLine(line); }
            while (!string.IsNullOrEmpty(line) && beginmsg.IsMatch(line))
            {
                String[] outputarray = new String[17];
                // get the index of the start of the msg
                if (fileMode)
                {
                    outputarray[0] = currentFileLoadProg.ToString();
                }
                else
                {
                    outputarray[0] = (streamData.Count - 1).ToString(); 
                }
                outputarray[1] = Regex.Match(line, @"(\d{4}-\d{2}-\d{2})").ToString();                             //date                                 
                outputarray[2] = Regex.Match(line, @"(\d{2}:\d{2}:\d{2}.\d{6})").ToString();                       //time            
                outputarray[3] = Regex.Match(line, @"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})").ToString();      //src IP                                                                        
                outputarray[4] = Regex.Matches(line, @"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")[1].ToString();      //dst IP           

                line = sread.ReadLine();
                if (line == null) { break; }
                if (!fileMode && DisplaySsh) { Console.WriteLine(line); }
                lock (_locker)
                {
                    if (fileMode) { UpdateFileLoadProgress(); }
                    else
                    { streamData.Add(line); }
                }                

                //check to match these only once. no need match a field if it is already found
                bool sipTwoDotOfound = false;
                bool callidFound = false;
                bool toFound = false;
                bool fromFound = false;
                bool SDPFopund = false;
                bool SDPIPFound = false;
                bool mAudioFound = false;
                bool uaservfound = false;
                while (!beginmsg.IsMatch(line)) //untill the begining of the next msg
                {
                    if (!sipTwoDotOfound && line.Contains("SIP/2.0") && !line.Contains("Via:"))
                    {
                        outputarray[5] = requestRgx.Match(line).ToString().Trim();
                        sipTwoDotOfound = true;
                    }
                    else if (!callidFound && callidRgx.IsMatch(line)) { outputarray[6] = callidRgx.Match(line).ToString().Trim(); callidFound = true; } // get call-id                    
                    else if (!toFound && toRgx.IsMatch(line)) { outputarray[7] = toRgx.Match(line).ToString().Trim(); toFound = true; } // get to:                    
                    else if (!fromFound && fromRgx.IsMatch(line)) { outputarray[8] = fromRgx.Match(line).ToString().Trim(); fromFound = true; } //get from                    
                    else if (!SDPFopund && line.Contains("Content-Type: application/sdp")) { outputarray[11] = " SDP"; SDPFopund = true; }
                    else if (!SDPIPFound && SDPIPRgx.IsMatch(line)) { outputarray[13] = SDPIPRgx.Match(line).ToString(); SDPIPFound = true; }
                    else if (!mAudioFound && mAudioRgx.IsMatch(line))
                    {
                        outputarray[14] = portRgx.Match(line).ToString().Trim();
                        outputarray[15] = codecRgx.Match(line).ToString().Trim();
                        if (outputarray[15] == "0") { outputarray[15] = "G711u"; }
                        else if (outputarray[15] == "8") { outputarray[15] = "G711a"; }
                        else if (outputarray[15] == "9") { outputarray[15] = "G722"; }
                        else if (outputarray[15] == "18") { outputarray[15] = "G729"; }
                        else { outputarray[15] = "rtp-payload type:" + outputarray[15]; }

                        mAudioFound = true;
                    }
                    else if (!uaservfound && uaRgx.IsMatch(line))
                    {
                        outputarray[16] = uaRgx.Match(line).ToString().Trim();
                        uaservfound = true;
                    }
                    else if (!uaservfound && serverRgx.IsMatch(line))
                    {
                        outputarray[16] = serverRgx.Match(line).ToString().Trim();
                        uaservfound = true;
                    }
                    else if (!uaservfound && occasRgx.IsMatch(line))
                    {
                        outputarray[16] = "occas";
                    }
                    line = sread.ReadLine();
                    if (line == null) { break; }
                    if (!fileMode && DisplaySsh) { Console.WriteLine(line); }
                    lock (_locker)
                    {
                        if (fileMode) { UpdateFileLoadProgress(); }
                        else
                        { streamData.Add(line); }
                    } 
                }
                // get the index of the end of the msg
                if (fileMode)
                {
                    outputarray[9] = currentFileLoadProg.ToString();
                }
                else
                {
                    outputarray[9] = (streamData.Count - 1).ToString();
                }
                outputarray[10] = "Gray";
                outputarray[12] = fileName; //add file name 
                if (outputarray[5] == null) { outputarray[5] = "Invalid SIP characters"; }
                if (sipTwoDotOfound)
                {
                    lock (_locker) { messages.Add(outputarray); }
                    if (!fileMode && !DisplaySsh)
                    {
                        string FrmtStr = String.Format("{3,-16} > {4,-16}{5} From:{8} To:{7} {15}", outputarray);
                        TopLine(FrmtStr.Substring(0, Math.Min(FrmtStr.Length, Console.BufferWidth-1)), 0);
                    }
                    bool getcallid = false;
                    if (outputarray[3] != outputarray[4])
                    {
                        if (outputarray[5].Contains("INVITE") || outputarray[5].Contains("NOTIFY")|| outputarray[5].Contains("REGISTER") || outputarray[5].Contains("SUBSCRIBE"))
                        {
                            //if (CallInvites == 0) { DisplaySsh = false; }
                            if (callLegs.Count > 0) // if it is not the first message
                            {
                                //check if call-id was not already gotten
                                for (int j = 0; j < callLegs.Count; j++)
                                {
                                    getcallid = true;

                                    if (callLegs[j][4] == outputarray[6]) // check if re-invite
                                    {
                                        getcallid = false;
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                getcallid = true;
                            }
                            if (getcallid == true)
                            {
                                // copy from msg input to arrayout
                                String[] arrayout = new String[10];
                                arrayout[0] = outputarray[1];//  date [0]
                                arrayout[1] = outputarray[2];//  time [1]
                                arrayout[2] = outputarray[7];//  To: [2]
                                arrayout[3] = outputarray[8];//  From: [3]
                                arrayout[4] = outputarray[6];//  Call-ID [4]
                                arrayout[5] = " ";                //  selected [5]  " " = not selected
                                arrayout[6] = outputarray[3];//  src IP [6]
                                arrayout[7] = outputarray[4];//  dst ip [7]
                                arrayout[8] = "filtered";
                                if (outputarray[5].Contains("INVITE")){ arrayout[9] = "invite"; CallInvites++; }
                                else if (outputarray[5].Contains("NOTIFY")) { arrayout[9] = "notify"; notifications++; }
                                else if (outputarray[5].Contains("REGISTER")) { arrayout[9] = "register"; registrations++; }
                                else if (outputarray[5].Contains("SUBSCRIBE")) { arrayout[9] = "subscribe"; subscriptions++; }
                                if (outputarray[6] != null)
                                {
                                    lock (_locker) { callLegs.Add(arrayout); }
                                    if (outputarray[5].Contains("INVITE")) { CallInvites++; }
                                }
                            }
                        }
                    }
                }
            }
        }
        else
        {
            lock (_locker)
            {
                if (fileMode) { UpdateFileLoadProgress(); }
                //else
                //{ streamData.Add(line); }
            }
            //if (!fileMode && DisplaySsh) { Console.WriteLine(line); }
        }
    }

    void UpdateFileLoadProgress()
    {
        currentFileLoadProg++;        
        if (currentFileLoadProg % 20000 == 0)
        {
            short x;
            x = (short)(currentFileLoadProg / 20000);
            TopLine("!", (short)(x-1));
        }
    }

    void CallDisplay(int position)
    {
        if (callLegsDisplayed.Count > 0)
        {
            //if the following conditions true , just add the calls to the bottom of the screen without redrawing
            if (!TermChange && !filterChange && callLegsDisplayedCountPrev != 0 && callLegsDisplayed.Count > callLegsDisplayedCountPrev)
            {
                if (callLegsDisplayed.Count > Console.WindowHeight)
                {
                    Console.BufferHeight = 10 + callLegsDisplayed.Count;
                }
                //Console.SetCursorPosition(0,  callLegsDisplayedCountPrev+4 );
                for (int i = callLegsDisplayedCountPrev; i < callLegsDisplayed.Count; i++)
                {
                    WriteScreenCallLine(callLegsDisplayed[i], i);
                }
            }
            else
            {
                filterChange = false;
                callLegsDisplayedCountPrev = callLegsDisplayed.Count;
                Console.WindowWidth = Math.Min(161, Console.LargestWindowWidth);
                Console.WindowHeight = Math.Min(44, Console.LargestWindowHeight);
                Console.BufferWidth = 200;
                ClearConsoleNoTop();
                Console.SetCursorPosition(0, 1);
                fakeCursor[0] = 0; fakeCursor[1] = 1;
                if (callLegsDisplayed.Count > Console.WindowHeight)
                {
                    Console.BufferHeight = 10 + callLegsDisplayed.Count;
                }
                WriteConsole("[Spacebar]-select calls [Enter]-for call flow [F]-filter [Q]-query all SIP msgs [Esc]-quit [N]-toggle NOTIFYs [R]-registrations [S]-subscriptions", headerTxtClr, headerBkgrdClr);
                if (!fileMode) { WriteLineConsole(" [T]-terminal [W]-write to file", headerTxtClr, headerBkgrdClr); } else { WriteLineConsole(" ", headerTxtClr, headerBkgrdClr); }
                String formatedStr = String.Format("{0,-2} {1,-6} {2,-10} {3,-12} {4,-45} {5,-45} {6,-16} {7,-16}", "*", "index", "date", "time", "from:", "to:", "src IP", "dst IP");
                WriteLineConsole(formatedStr, headerTxtClr, headerBkgrdClr);
                WriteLineConsole(new String('-', 160), headerTxtClr, headerBkgrdClr);
                int i = 0;
                foreach (String[] ary in callLegsDisplayed)
                {
                    if ((Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)) { break; }
                    WriteScreenCallLine(ary, i);
                    i++;
                }
            }
            string footerOne = "Number of SIP messages found : " + messages.Count.ToString();
            string footerTwo = "Number of Call legs found : " + CallInvites.ToString();
            string footerThree = "Number of Call legs filtered : " + callLegsDisplayed.Count.ToString();
            WriteScreen(footerOne + new String(' ', Console.BufferWidth - footerOne.Length), 0, (short)(callLegsDisplayed.Count + 4), footerTxtClr, footerBkgrdClr);
            WriteScreen(footerTwo + new String(' ', Console.BufferWidth - footerTwo.Length), 0, (short)(callLegsDisplayed.Count + 5), footerTxtClr, footerBkgrdClr);
            WriteScreen(footerThree + new String(' ', Console.BufferWidth - footerThree.Length), 0, (short)(callLegsDisplayed.Count + 6), footerTxtClr, footerBkgrdClr);
            Console.SetCursorPosition(0, position + 4);
            Console.BackgroundColor = fieldConsoleTxtClr;
            Console.ForegroundColor = fieldConsoleBkgrdClr;
            CallLine(callLegsDisplayed[position], position);
            Console.SetCursorPosition(0, position + 4);
            Console.BackgroundColor = fieldConsoleBkgrdClr;
            Console.ForegroundColor = fieldConsoleTxtClr;
        }
        else // if no calls are found yet just diplay the header and footer
        {
            Console.WindowWidth = Math.Min(161, Console.LargestWindowWidth);
            Console.WindowHeight = Math.Min(44, Console.LargestWindowHeight);
            Console.BufferWidth = 200;
            ClearConsoleNoTop();
            Console.SetCursorPosition(0, 1);
            fakeCursor[0] = 0; fakeCursor[1] = 1;
            WriteConsole("[Spacebar]-select calls [Enter]-for call flow [F]-filter [Q]-query all SIP msgs [Esc]-quit [N]-toggle NOTIFYs [R]-registrations [S]-subscriptions", headerTxtClr, headerBkgrdClr);
            if (!fileMode) { WriteLineConsole(" [T]-terminal [W]-write to file", headerTxtClr, headerBkgrdClr); } else { WriteLineConsole(" ", headerTxtClr, headerBkgrdClr); }
            String formatedStr = String.Format("{0,-2} {1,-6} {2,-10} {3,-12} {4,-45} {5,-45} {6,-16} {7,-16}", "*", "index", "date", "time", "from:", "to:", "src IP", "dst IP");
            WriteLineConsole(formatedStr, headerTxtClr, headerBkgrdClr);
            WriteLineConsole(new String('-', 160), headerTxtClr, headerBkgrdClr);
            string footerOne = "Number of SIP messages found : " + messages.Count.ToString();
            string footerTwo = "Number of Call legs found : " + CallInvites.ToString();
            string footerThree = "Number of Call legs filtered : " + callLegsDisplayed.Count.ToString();
            WriteScreen(footerOne + new String(' ', Console.BufferWidth - footerOne.Length), 0, (short)(callLegsDisplayed.Count + 4), footerTxtClr, footerBkgrdClr);
            WriteScreen(footerTwo + new String(' ', Console.BufferWidth - footerTwo.Length), 0, (short)(callLegsDisplayed.Count + 5), footerTxtClr, footerBkgrdClr);
            WriteScreen(footerThree + new String(' ', Console.BufferWidth - footerThree.Length), 0, (short)(callLegsDisplayed.Count + 6), footerTxtClr, footerBkgrdClr);
        }          
    }

    void CallLine(string[] InputCallLegs, int indx)
    {
        if (InputCallLegs[5] == "*") { Console.ForegroundColor = fieldConsoleSelectClr; } 
        Console.WriteLine("{0,-2} {1,-6} {2,-10} {3,-12} {5,-45} {4,-45} {6,-16} {7,-17}"
            , InputCallLegs[5]
            , indx
            , InputCallLegs[0]
            , ((InputCallLegs[1]).Substring(0, 11)) ?? String.Empty
            , (InputCallLegs[2].Split('@')[0].Substring(0, Math.Min(44, InputCallLegs[2].Split('@')[0].Length))) ?? String.Empty
            , (InputCallLegs[3].Split('@')[0].Substring(0, Math.Min(44, InputCallLegs[3].Split('@')[0].Length))) ?? String.Empty
            , InputCallLegs[6]
            , InputCallLegs[7]);
        Console.ForegroundColor = fieldConsoleTxtClr;
    }

    void WriteScreenCallLine(string[] callLeg, int indx)
    {
        AttrColor txtColor;
        short y = (short)(indx + 4);
        if (callLeg[5] == "*") { txtColor = fieldAttrSelectClr; } else { txtColor = fieldAttrTxtClr; }
        string formatedStr = String.Format("{0,-2} {1,-6} {2,-10} {3,-12} {5,-45} {4,-45} {6,-16} {7,-17}"
            , callLeg[5]
            , indx
            , callLeg[0]
            , callLeg[1].Substring(0, 11)
            , callLeg[2].Split('@')[0].Substring(0, Math.Min(44, callLeg[2].Split('@')[0].Length))
            , callLeg[3].Split('@')[0].Substring(0, Math.Min(44, callLeg[3].Split('@')[0].Length))
            , callLeg[6]
            , callLeg[7]);
        WriteScreen(formatedStr, 0, y, txtColor, fieldAttrBkgrdClr);
    }        

    void CallFilter(String[] filter,bool notify,string method)
    {
        callLegsDisplayed.Clear();
        List<string[]> callLegsCopy = callLegs.ToList(); //callLegs may be modified in another thread. a copy is made so it can be searched 
        
        if (!string.IsNullOrEmpty(filter[0]))
        {
            for (int i = 0; i < callLegsCopy.Count; i++)
            {
                bool addcall = false;
                foreach (String callitem in callLegsCopy[i])
                {
                    foreach (String filteritem in filter)
                    {
                        if (callitem.Contains(filteritem))
                        {
                            if (notify || callLegsCopy[i][9] == method) { addcall = true; }
                        }                             
                    }
                }
                if (addcall) { callLegsDisplayed.Add(callLegsCopy[i]); } 
            }
        }
        else
        {
            for (int i = 0; i < callLegsCopy.Count; i++)
            {
                bool addcall = false;
                foreach (String callitem in callLegsCopy[i])
                {
                    foreach (String filteritem in filter)
                    {                        
                        if (notify || callLegsCopy[i][9] == method) { addcall = true; }                        
                    }
                }
                if (addcall) { callLegsDisplayed.Add(callLegsCopy[i]); }
            }
        }        
    }
    
    void CallSelect(List<string[]> callLegs, List<string[]> messages)
    {
        int selected = 0;
        bool done = false;
        int position = 0;
        bool notify = false;
        string method = "invite";
        String[] filter = new String[20];
        int CallInvitesPrev = 0;
        int prevRegistrations = 0;
        int prevsubscriptions = 0;
        //while (CallInvites < 1 || notifications < 1 || registrations < 1 || subscriptions < 1 )
        while(DisplaySsh)
        {
           //do nothing
        }
        CallFilter(filter,notify,method);
        CallDisplay(position);
        ConsoleKeyInfo keypressed;
        while (done == false)
        {
            //dynamicly update the list if any of the following change
            while (DisplaySsh || !Console.KeyAvailable )
            {
                if (!DisplaySsh)
                {
                    if (method == "invite" && CallInvites > CallInvitesPrev)
                    {
                        CallInvitesPrev = CallInvites;
                        CallFilter(filter, notify, method);
                        CallDisplay(position);
                    }
                    if (method == "register" && registrations > prevRegistrations)
                    {
                        prevRegistrations = registrations;
                        CallFilter(filter, notify, method);
                        CallDisplay(position);
                    }
                    if (method == "subscribe" && subscriptions > prevsubscriptions)
                    {
                        prevsubscriptions = subscriptions;
                        CallFilter(filter, notify, method);
                        CallDisplay(position);
                    }
                }
                if(TermChange)
                {                    
                    CallFilter(filter, notify, method);
                    CallDisplay(position);
                    TermChange = false;
                }                
            }
            keypressed = Console.ReadKey(true);
            if (keypressed.Key == ConsoleKey.DownArrow)
            {
                if (position < callLegsDisplayed.Count - 1)
                {
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                    CallLine(callLegsDisplayed[position], position);
                    position++;
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                    CallLine(callLegsDisplayed[position], position);
                    Console.CursorTop -= 1;
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                }
            }
            if (keypressed.Key == ConsoleKey.PageDown)
            {
                if (position + 40 < callLegsDisplayed.Count - 1)
                {
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                    CallLine(callLegsDisplayed[position], position);
                    Console.CursorTop += 39;
                    position += 40;
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                    CallLine(callLegsDisplayed[position], position);
                    Console.CursorTop -= 1;
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                }
                else
                {
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                    CallLine(callLegsDisplayed[position], position);
                    Console.CursorTop = callLegsDisplayed.Count - 1 + 4;
                    position = callLegsDisplayed.Count - 1;
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                    CallLine(callLegsDisplayed[position], position);
                    Console.CursorTop -= 1;
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                }
            }
            if (keypressed.Key == ConsoleKey.UpArrow)
            {
                if (position > 0)
                {
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                    CallLine(callLegsDisplayed[position], position);
                    Console.CursorTop -= 2;     //move cursor up two since writline advances one
                    position--;
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                    CallLine(callLegsDisplayed[position], position);
                    Console.CursorTop -= 1;
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                }
                else
                {
                    Console.SetCursorPosition(0, 0);
                    Console.SetCursorPosition(0, 4);
                }
            }
            if (keypressed.Key == ConsoleKey.PageUp)
            {
                if (position > 40)
                {
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                    CallLine(callLegsDisplayed[position], position);
                    Console.CursorTop -= 41;     //move cursor up two since writline advances one
                    position -= 40;
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                    CallLine(callLegsDisplayed[position], position);
                    Console.CursorTop -= 1;
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                }
                else
                {
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                    CallLine(callLegsDisplayed[position], position);
                    Console.CursorTop = 4;     //move cursor up two since writline advances one
                    position = 0;
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                    CallLine(callLegsDisplayed[position], position);
                    Console.CursorTop -= 1;
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                }
                if (position == 0)
                {
                    Console.SetCursorPosition(0, 0);
                    Console.SetCursorPosition(0, 4);
                }

            }
            if (callLegsDisplayed.Count > 0 && keypressed.Key == ConsoleKey.Spacebar)
            {
                 if (callLegsDisplayed[position][5] == "*")
                {
                    callLegsDisplayed[position][5] = " ";
                    selected--;
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                    CallLine(callLegsDisplayed[position], position);
                    Console.CursorTop = Console.CursorTop - 1;
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                }
                else
                {
                    callLegsDisplayed[position][5] = "*";
                    selected++;
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                    CallLine(callLegsDisplayed[position], position);
                    Console.CursorTop = Console.CursorTop - 1;
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                }
            }
            if (selected > 0 && keypressed.Key == ConsoleKey.Enter)
            {
                FlowSelect();   //select SIP message from the call flow diagram                        
                filterChange = true;
                CallFilter(filter, notify, method);
                CallDisplay(position);
            }
            if (keypressed.Key == ConsoleKey.Escape)
            {
                Console.WriteLine(@"  +-------------------------------------+\  ");
                Console.WriteLine(@"  |  Are you sure you wantto quit? Y/N? | | ");
                Console.WriteLine(@"  +-------------------------------------+ | ");
                Console.WriteLine(@"   \_____________________________________\| ");
                switch (Console.ReadKey(true).Key)
                {
                    case ConsoleKey.Y:
                        IsRunning = false;
                        Console.Clear();
                        System.Environment.Exit(0);
                        break;
                    case ConsoleKey.N:
                        filterChange = true;
                        CallFilter(filter, notify, method);
                        CallDisplay(position);                        
                        break;
                }
            }
            if (keypressed.Key == ConsoleKey.Q)
            {
                do
                {
                    ListAllMsg(messages);
                    Console.WriteLine(@"  +--------------------------------------------------------------------+\  ");
                    Console.WriteLine(@"  |  Press any key to query SIP messages again or press [esc] to quit | | ");
                    Console.WriteLine(@"  +-------------------------------------------------------------------+ | ");
                    Console.WriteLine(@"   \___________________________________________________________________\| ");
                } while (Console.ReadKey(true).Key != ConsoleKey.Escape);
                filterChange = true;
                CallFilter(filter, notify, method);
                CallDisplay(position);                
            }
            if (keypressed.Key == ConsoleKey.F)
            {
                filterChange = true;
                do
                {
                    Console.WriteLine(@"  +------------------------------------------------------------------------------------------------------------------------------------+\  ");
                    Console.WriteLine(@"  | Enter space separated items like extensions, names or IP. Items are OR. Case sensitive. Leave blank for no Filter.                 | | ");
                    Console.WriteLine(@"  |                                                                                                                                    | | ");
                    Console.WriteLine(@"  +------------------------------------------------------------------------------------------------------------------------------------+ | ");
                    Console.WriteLine(@"   \____________________________________________________________________________________________________________________________________\| ");
                    Console.CursorTop -= 3;
                    Console.CursorLeft += 4;
                    filter = Console.ReadLine().Split(' ');
                    CallFilter(filter, notify, method);
                    if (callLegsDisplayed.Count == 0)
                    {
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.CursorTop = Console.CursorTop - 1;
                        Console.WriteLine("  | No calls found. Press any key to continue");
                        Console.ForegroundColor = ConsoleColor.Gray;
                        Console.CursorVisible = true;
                        Console.ReadKey(true);
                        Console.CursorTop -= 4;
                    }
                }
                while (callLegsDisplayed.Count == 0);
                position = 0;
                CallDisplay(position);
                Console.SetCursorPosition(0, 0);
                Console.SetCursorPosition(0, 4);
            }
            if (keypressed.Key == ConsoleKey.N)
            {
                position = 0;
                if (notify == false) { notify = true; } else { notify = false; }
                filterChange = true;
                CallFilter(filter, notify, method);
                CallDisplay(position);
            }
            if (!fileMode && keypressed.Key == ConsoleKey.T)
            {
                Console.Clear();
                for(int i = streamData.Count-40; i < streamData.Count; i++)
                {
                    Console.WriteLine(streamData[i]);
                }
                DisplaySsh = true;                
            }
            if (!fileMode && keypressed.Key == ConsoleKey.W)
            {
                Console.WriteLine(@"  +-------------------------------------------------------------------+\  ");
                Console.WriteLine(@"  | Enter the file name to the data will be writen to:                | | ");
                Console.WriteLine(@"  |                                                                   | | ");
                Console.WriteLine(@"  +-------------------------------------------------------------------+ | ");
                Console.WriteLine(@"   \___________________________________________________________________\| ");
                Console.CursorTop -= 3;
                Console.CursorLeft += 4;
                string writeFileName = Console.ReadLine();
                if (String.IsNullOrEmpty(writeFileName))
                {
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.CursorTop = Console.CursorTop - 1;
                    Console.WriteLine("  | No file name was entered. Press any key to continue");
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.CursorVisible = true;
                    Console.ReadKey(true);
                    Console.CursorTop -= 4;
                }
                else
                {
                    File.WriteAllLines(writeFileName, streamData);
                }
                filterChange = true;
                CallFilter(filter, notify, method);
                CallDisplay(position);
            }
            if (method != "register" && keypressed.Key == ConsoleKey.R)
            {
                string prevMethod = method;
                filterChange = true;
                method = "register";
                ClearSelectedCalls();
                selected = 0;
                position = 0;
                CallFilter(filter, notify, method);
                CallDisplay(position);
                Console.SetCursorPosition(0, 0);
                Console.SetCursorPosition(0, 4);
            }
            if (method != "subscribe" && keypressed.Key == ConsoleKey.S)
            {
                string prevMethod = method;
                filterChange = true;
                ClearSelectedCalls();
                selected = 0;
                method = "subscribe";
                position = 0;
                CallFilter(filter, notify, method);
                CallDisplay(position);
                Console.SetCursorPosition(0, 0);
                Console.SetCursorPosition(0, 4);
            }
            if (method != "invite" && keypressed.Key == ConsoleKey.I)
            {
                string prevMethod = method;
                filterChange = true;
                method = "invite";
                selected = 0;
                ClearSelectedCalls();
                position = 0;
                CallFilter(filter, notify, method);
                CallDisplay(position);
                Console.SetCursorPosition(0, 0);
                Console.SetCursorPosition(0, 4);
            }
        }        
    }

    void ClearSelectedCalls()
    {
        for (int i = 0; i < callLegsDisplayed.Count; i++)
        {
            callLegsDisplayed[i][5] = " ";
        }
    }

    static List<string[]> SelectMessages(List<string[]> messages, List<string[]> callLegs)
    {
        List<string[]> outputlist = new List<string[]>();
        List<string> callids = new List<string>();
        CallLegColors callcolor = CallLegColors.Green;
        for (int i = 0; i < callLegs.Count; i++)
        {
            if (callLegs[i][5] == "*")
            {
                callids.Add(callLegs[i][4]);
            }
        }
        foreach (string cid in callids)
        {
            for (int i = 0; i < messages.Count; i++)
            {
                if (cid == messages[i][6])
                {
                    messages[i][10] = callcolor.ToString();
                }
            }
            if (callcolor == CallLegColors.DarkMagenta) { callcolor = CallLegColors.Green; } else { callcolor++; }
        }
        for (int i = 0; i < messages.Count; i++)
        {
            if (callids.Contains(messages[i][6]))
            {
                if (messages[i][3] != messages[i][4])
                {
                    outputlist.Add(messages[i]);
                }
            }
        }
        return outputlist;
    }

    static List<string> GetIps(List<string[]> selectedmessages)
    {
        List<string> ips = new List<string>();
        for (int i = 0; i < selectedmessages.Count; i++)
        {
            if (!ips.Contains(selectedmessages[i][3]))
            {
                ips.Add(selectedmessages[i][3]);
            }
            if (!ips.Contains(selectedmessages[i][4]))
            {
                ips.Add(selectedmessages[i][4]);
            }
        }
        return ips;
    }

    void Flow(List<string[]> selectedmessages,bool addToEnd,int prevNumSelectMsg)
    {
        List<string> ips = new List<string>();
        ips = GetIps(selectedmessages); //get the IP addresses of the selected SIP messages for the top of the screen     
        if (!addToEnd || ips.Count> numSelectdIps)
        {
            numSelectdIps = ips.Count;
            Console.SetCursorPosition(0, 1);
            fakeCursor[0] = 0; fakeCursor[1] = 1;
            if (selectedmessages.Count > Console.WindowHeight)
            {
                Console.BufferHeight = Math.Min(10 + selectedmessages.Count, Int16.MaxValue - 1);
            }
            flowWidth = 24;
            WriteConsole(new String(' ', 17), fieldAttrTxtClr, fieldAttrBkgrdClr);
            foreach (string ip in ips)
            {
                flowWidth = flowWidth + 29;
                if (flowWidth > Console.WindowWidth)
                {
                    Console.BufferWidth = flowWidth;
                }
                WriteConsole(ip + new String(' ', 29 - ip.Length), fieldAttrTxtClr, fieldAttrBkgrdClr);
            }
            WriteLineConsole("", fieldAttrTxtClr, fieldAttrBkgrdClr);
            WriteConsole(new String(' ', 17), fieldAttrTxtClr, fieldAttrBkgrdClr);
            foreach (string ip in ips)
            {
                string ua = "";
                foreach (string[] ary in selectedmessages)
                {
                    if (ary[3] == ip && ary[16] != null)
                    {
                        ua = ary[16].Substring(0, Math.Min(15, ary[16].Length));
                        break;
                    }
                }
                WriteConsole(ua + new String(' ', 29 - ua.Length), fieldAttrTxtClr, fieldAttrBkgrdClr);
            }
            WriteLineConsole("", fieldAttrTxtClr, fieldAttrBkgrdClr);
            WriteLineConsole(new String('-', flowWidth - 1), fieldAttrTxtClr, fieldAttrBkgrdClr);
            foreach (string[] msg in selectedmessages)
            {
                //if ((Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)) { break; }
                WriteMessageLine(msg, ips, false);
            }
            WriteLineConsole(new String('-', flowWidth - 1), fieldAttrTxtClr, fieldAttrBkgrdClr);
        }
        else
        {
            for (int i = prevNumSelectMsg; i < selectedmessages.Count; i++)
            {
                fakeCursor[0] = 0; fakeCursor[1] = i+4;
                WriteMessageLine(selectedmessages[i], ips, false);
                WriteLineConsole(new String('-', flowWidth - 1), fieldAttrTxtClr, fieldAttrBkgrdClr);
            }
        }
    }

    void MessageLine(string[] message, List<string> ips, bool invert)
    {
        //get the index of the src and dst IP
        int srcindx = ips.IndexOf(message[3]);
        int dstindx = ips.IndexOf(message[4]);
        bool isright = false;
        int lowindx = 0;
        int hiindx = 0;
        string space = new String(' ', 28) + "|";
        if (srcindx < dstindx)
        {
            lowindx = srcindx;
            hiindx = dstindx;
            isright = true;
        }
        if (srcindx > dstindx)
        {
            lowindx = dstindx;
            hiindx = srcindx;
            isright = false;
        }
        if (invert)
        {
            Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;
            Console.ForegroundColor = fieldConsoleTxtInvrtClr;
        }
        else
        {
            Console.BackgroundColor = fieldConsoleBkgrdClr;
            Console.ForegroundColor = fieldConsoleTxtClr;
        }
        Console.Write("{0,-10} {1,-12}|", message[1], message[2].Substring(0, 11));
        for (int i = 0; i < lowindx; i++)
        {
            Console.Write(space);
        }
        Console.ForegroundColor = (ConsoleColor)Enum.Parse(typeof(ConsoleColor), message[10]);

        if (isright) { Console.Write("-"); }
        else { Console.Write("<"); }
        string firstline = message[5].Replace("SIP/2.0 ", "");
        string displayedline = firstline.Substring(0, Math.Min(18, firstline.Length)) + message[11];
        int fullline = 29 * (hiindx - (lowindx + 1));
        double leftline = ((26 - displayedline.Length) + fullline) / 2; //
        Console.Write(new String('-', (int)Math.Floor(leftline)));
        Console.Write(displayedline);
        double rightline = 26 - leftline - displayedline.Length + fullline; 
        Console.Write(new String('-', (int)rightline));
        if (isright) { Console.Write(">"); }
        else { Console.Write("-"); }
        if (invert)
        {
            Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;
            Console.ForegroundColor = fieldConsoleTxtInvrtClr;
        }
        else
        {
            Console.BackgroundColor = fieldConsoleBkgrdClr;
            Console.ForegroundColor = fieldConsoleTxtClr;
        }
        Console.Write("|");

        for (int i = 0; i < ips.Count - 1 - hiindx; i++)
        {
            Console.Write(space);
        }
        if (message[13] != null) { Console.Write(" {0}:{1} {2}", message[13], message[14], message[15]); }
        Console.BackgroundColor = fieldConsoleBkgrdClr;
        Console.ForegroundColor = fieldConsoleTxtClr;
        Console.WriteLine();
    }

    void WriteMessageLine(string[] message, List<string> ips, bool invert)
    {
        AttrColor TxtColor;
        AttrColor BkgrdColor;
        AttrColor CallTxtColor;

        //get the index of the src and dst IP
        int srcindx = ips.IndexOf(message[3]);
        int dstindx = ips.IndexOf(message[4]);
        bool isright = false;
        int lowindx = 0;
        int hiindx = 0;
        string space = new String(' ', 28) + "|";
        if (srcindx < dstindx)
        {
            lowindx = srcindx;
            hiindx = dstindx;
            isright = true;
        }
        if (srcindx > dstindx)
        {
            lowindx = dstindx;
            hiindx = srcindx;
            isright = false;
        }
        if (invert)
        {
            TxtColor = fieldAttrTxtInvrtClr;
            BkgrdColor = fieldAttrBkgrdInvrtClr;
        }
        else
        {
            TxtColor = fieldAttrTxtClr;
            BkgrdColor = fieldAttrBkgrdClr;
        }
        string formatedStr = String.Format("{0,-10} {1,-12}|", message[1], message[2].Substring(0, 11));
        WriteConsole(formatedStr, TxtColor, BkgrdColor);
        for (int i = 0; i < lowindx; i++)
        {
            WriteConsole(space, TxtColor, BkgrdColor);
        }
        CallTxtColor = (AttrColor)Enum.Parse(typeof(AttrColor), message[10]);

        if (isright) { WriteConsole("-", CallTxtColor, BkgrdColor); }
        else { WriteConsole("<", CallTxtColor, BkgrdColor); }
        string firstline = message[5].Replace("SIP/2.0 ", "");
        string displayedline = firstline.Substring(0, Math.Min(18, firstline.Length)) + message[11];
        int fullline = 29 * (hiindx - (lowindx + 1));
        double leftline = ((26 - displayedline.Length) + fullline) / 2; //
        WriteConsole(new String('-', (int)Math.Floor(leftline)), CallTxtColor, BkgrdColor);
        WriteConsole(displayedline, CallTxtColor, BkgrdColor);
        double rightline = 26 - leftline - displayedline.Length + fullline;
        WriteConsole(new String('-', (int)rightline), CallTxtColor, BkgrdColor);
        if (isright) { WriteConsole(">", CallTxtColor, BkgrdColor); }
        else { WriteConsole("-", CallTxtColor, BkgrdColor); }
        WriteConsole("|", TxtColor, BkgrdColor);

        for (int i = 0; i < ips.Count - 1 - hiindx; i++)
        {
            WriteConsole(space, TxtColor, BkgrdColor);
        }
        if (message[13] != null)
        {
            String AnotherFrmtStr = String.Format(" {0}:{1} {2}", message[13], message[14], message[15]);
            WriteConsole(AnotherFrmtStr, TxtColor, BkgrdColor);
        }
        WriteLineConsole("", TxtColor, BkgrdColor);
    }

    void FlowSelect()
    {
        List<String[]> selectedmessages = new List<string[]>();
        selectedmessages = SelectMessages(messages, callLegsDisplayed);
        int prevNumSelectMsg = selectedmessages.Count;        
        List<string> ips = new List<string>();
        ips = GetIps(selectedmessages);
        int position = 0;
        Console.BackgroundColor = fieldConsoleBkgrdClr;
        Console.ForegroundColor = fieldConsoleTxtClr;
        if (selectedmessages.Count > Console.BufferHeight) { Console.BufferHeight = Math.Min(selectedmessages.Count + 20, Int16.MaxValue - 1); }
        ClearConsoleNoTop();
        Flow(selectedmessages, false,0);  //display call flow Diagram
        Console.SetCursorPosition(0, 0);   //brings window to the very top
        Console.SetCursorPosition(0, 4);
        MessageLine(selectedmessages[0], ips, true);
        Console.CursorTop -= 1;
        bool done = false;
        while (done == false)
        {
            ConsoleKeyInfo keypress;
            while (!Console.KeyAvailable)
            {
                //lock (_locker)
                //{
                    selectedmessages = SelectMessages(messages, callLegsDisplayed);
                //}
                if (selectedmessages.Count > prevNumSelectMsg)
                {
                    Flow(selectedmessages, true, prevNumSelectMsg);
                    prevNumSelectMsg = selectedmessages.Count;
                }
            }
            keypress = Console.ReadKey(true);
            if (keypress.Key == ConsoleKey.DownArrow)
            {
                if (position < selectedmessages.Count - 1)
                {
                    MessageLine(selectedmessages[position], ips, false);
                    position++;
                    MessageLine(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
            }
            if (keypress.Key == ConsoleKey.PageDown)
            {
                if (position + 40 < selectedmessages.Count - 1)
                {
                    MessageLine(selectedmessages[position], ips, false);
                    position += 40;
                    Console.CursorTop += 39;
                    MessageLine(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
                else
                {
                    MessageLine(selectedmessages[position], ips, false);
                    position = selectedmessages.Count - 1;
                    Console.CursorTop = selectedmessages.Count - 1 + 4;
                    MessageLine(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
            }
            if (keypress.Key == ConsoleKey.UpArrow)
            {
                if (position > 0)
                {
                    MessageLine(selectedmessages[position], ips, false);
                    Console.CursorTop -= 2;
                    position--;
                    MessageLine(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
                else
                {
                    Console.SetCursorPosition(0, 0);   //brings window to the very top
                    Console.SetCursorPosition(0, 4);
                }
            }
            if (keypress.Key == ConsoleKey.PageUp)
            {
                if (position > 39)
                {
                    MessageLine(selectedmessages[position], ips, false);
                    Console.CursorTop -= 41;
                    position -= 40;
                    MessageLine(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
                else
                {
                    MessageLine(selectedmessages[position], ips, false);
                    Console.CursorTop = 4;
                    position = 0;
                    MessageLine(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
                if (position == 0)
                {
                    Console.SetCursorPosition(0, 0);   //brings window to the very top
                    Console.SetCursorPosition(0, 4);
                }
            }
            if ((keypress.Key == ConsoleKey.Enter) || (keypress.Key == ConsoleKey.Spacebar))
            {
                DisplayMessage(position, selectedmessages);
                Console.BackgroundColor = fieldConsoleBkgrdClr;
                Console.ForegroundColor = fieldConsoleTxtClr;
                if (selectedmessages.Count > Console.BufferHeight) { Console.BufferHeight = Math.Min(selectedmessages.Count + 20, Int16.MaxValue - 1); }
                Flow(selectedmessages,false,0);  //display call flow Diagram
                if (position == 0)
                {
                    Console.SetCursorPosition(0, 0);   //brings window to the very top
                    Console.SetCursorPosition(0, 4);
                    MessageLine(selectedmessages[0], ips, true);
                    Console.CursorTop -= 1;
                }
                else
                {
                    Console.SetCursorPosition(0, (position > 17) ? position - 17 : 0);
                    Console.SetCursorPosition(0, position + 4);
                    MessageLine(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
            }
            if (keypress.Key == ConsoleKey.Escape)
            {
                done = true;
            }
        }
        return;
    }

    void DisplayMessage(int msgindxselected, List<string[]> messages)
    {
        int msgStartIdx = Int32.Parse(messages[msgindxselected][0]);
        int msgEndIdx = Int32.Parse(messages[msgindxselected][9]);        
        if ((msgEndIdx - msgStartIdx) > Console.BufferHeight)
        {
            Console.BufferHeight = Math.Min(5 + (msgEndIdx - msgStartIdx), Int16.MaxValue - 1);
        }
        ClearConsoleNoTop();
        Console.SetCursorPosition(0, 1);
        fakeCursor[0] = 0; fakeCursor[1] = 1;
        Console.WriteLine("From line " + messages[msgindxselected][0] + " to " + messages[msgindxselected][9] + " from file " + messages[msgindxselected][12]);
        if (fileMode)
        {
            using (StreamReader sr = new StreamReader(messages[msgindxselected][12]))
            {
                string line = "";
                Console.Write("Finding lines from file");
                long progress = 0;
                for (int i = 0; i < Int32.Parse(messages[msgindxselected][0]); i++)
                {
                    progress++;
                    if (progress == 10000)
                    {
                        Console.Write(".");
                        progress = 0;
                    }
                    line = sr.ReadLine();
                }
                Console.WriteLine();
                Console.WriteLine(line);
                for (int j = msgStartIdx; j < msgEndIdx; j++)
                {
                    Console.WriteLine(sr.ReadLine());
                }
                sr.Close();
            }
        }
        else
        {
            for (int i = msgStartIdx; i <= msgEndIdx; i++)
            {
                Console.WriteLine(streamData[i]);
            }
        }
        Console.SetCursorPosition(0, 1);
        fakeCursor[0] = 0; fakeCursor[1] = 1;
        ConsoleKeyInfo keypressed;
        while (!((keypressed = Console.ReadKey(true)).Key == ConsoleKey.Escape))
        {
            if (Console.CursorTop < Console.BufferHeight - 1 && keypressed.Key == ConsoleKey.DownArrow)
            {
                Console.CursorTop++;
            }
            if (Console.CursorTop > 0 && keypressed.Key == ConsoleKey.UpArrow)
            {
                Console.CursorTop--;
            }
        }
    }

    void ListAllMsg(List<string[]> messages)
    {
        List<string[]> filtered = new List<string[]>();
        int maxline = 0;
        bool done = false;
        int position = 0;
        //string MsgLine;
        int MsgLineLen;
        ClearConsoleNoTop();
        Console.BufferWidth = 500;
        Console.SetCursorPosition(0, 1);
        Console.WriteLine("Enter regex to search. Max lines displayed are 32765. example: for all the msg to/from 10.28.160.42 at 16:40:11 use 16:40:11.*10.28.160.42");
        Console.WriteLine("Data format: line number|date|time|src IP|dst IP|first line of SIP msg|From:|To:|Call-ID|line number|color|has SDP|filename|SDP IP|SDP port|SDP codec|useragent");
        string strginput = Console.ReadLine();
        ClearConsoleNoTop();
        Console.SetCursorPosition(0, 1);
        fakeCursor[0] = 0; fakeCursor[1] = 1;
        if (string.IsNullOrEmpty(strginput))
        {
            Console.WriteLine("You must enter a regex");
            Console.ReadKey(true);
            done = true;
        }
        else
        {
            Regex regexinput = new Regex(strginput);
            for (int i = 0; i < messages.Count;i++ )
            {
                string[] ary = messages[i];
                if ((Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)) { break; }
                if (regexinput.IsMatch(string.Join(" ", ary)))
                {
                    //MsgLine = string.Join("|", ary); 
                    MsgLineLen = string.Join(" ", ary).Length + 28;
                    if (MsgLineLen >= Console.BufferWidth) { Console.BufferWidth = MsgLineLen + 1; }
                    WriteLineConsole(String.Format("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", ary), fieldAttrTxtClr, fieldAttrBkgrdClr);
                    filtered.Add(ary);
                    maxline++;
                    if (maxline > 32700) { break; }
                    if (maxline > Console.BufferHeight) { Console.BufferHeight = maxline; }
                    
                }
            }
            if (filtered.Count == 0)
            {
                Console.WriteLine("NO search matches found. Press any key to continue");
                Console.ReadKey(true);
                return;
            }
            Console.SetCursorPosition(0, 1);
            
            Console.BackgroundColor = fieldConsoleTxtClr;
            Console.ForegroundColor = fieldConsoleBkgrdClr;
            Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
            Console.CursorTop -= 1;
            Console.BackgroundColor = fieldConsoleBkgrdClr;
            Console.ForegroundColor = fieldConsoleTxtClr;
        }
        while (!done)
        {
            ConsoleKeyInfo keypressed = Console.ReadKey(true);
            switch (keypressed.Key)
            {
                case ConsoleKey.DownArrow:
                    if (position < filtered.Count - 1)
                    {
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        position++;
                        Console.BackgroundColor = fieldConsoleTxtClr;
                        Console.ForegroundColor = fieldConsoleBkgrdClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        Console.CursorTop -= 1;
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                    }
                    break;

                case ConsoleKey.PageDown:
                    if (position + 40 < filtered.Count - 1)
                    {
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        Console.CursorTop += 39;
                        position += 40;
                        Console.BackgroundColor = fieldConsoleTxtClr;
                        Console.ForegroundColor = fieldConsoleBkgrdClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        Console.CursorTop -= 1;
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                    }
                    break;

                case ConsoleKey.UpArrow:
                    if (position > 0)
                    {
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        position--;
                        Console.CursorTop -= 2;
                        Console.BackgroundColor = fieldConsoleTxtClr;
                        Console.ForegroundColor = fieldConsoleBkgrdClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        Console.CursorTop -= 1;
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                    }
                    break;
                case ConsoleKey.PageUp:
                    if (position > 39)
                    {
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        position -= 40;
                        Console.CursorTop -= 41;
                        Console.BackgroundColor = fieldConsoleTxtClr;
                        Console.ForegroundColor = fieldConsoleBkgrdClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        Console.CursorTop -= 1;
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                    }
                    break;

                case ConsoleKey.Enter:
                    DisplayMessage(position, filtered);
                    Console.Clear();
                    Console.BufferWidth = 500;
                    if (filtered.Count > Console.WindowHeight)
                    {
                        Console.BufferHeight = filtered.Count + 10;
                    }                    
                    Console.SetCursorPosition(0, 0);
                    foreach (string[] line in filtered)
                    {
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", line);
                    }
                    Console.SetCursorPosition(0, position);
                    Console.BackgroundColor = fieldConsoleTxtClr;
                    Console.ForegroundColor = fieldConsoleBkgrdClr;
                    Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                    Console.CursorTop = Console.CursorTop - 1;
                    Console.BackgroundColor = fieldConsoleBkgrdClr;
                    Console.ForegroundColor = fieldConsoleTxtClr;
                    break;

                case ConsoleKey.Escape:
                    done = true;
                    break;
            }
        }
    }
}

public class ConsoleBuffer
{

    private static SafeFileHandle _hBuffer = null;

    static ConsoleBuffer()
    {
        const int STD_OUTPUT_HANDLE = -11;
        _hBuffer = GetStdHandle(STD_OUTPUT_HANDLE);

        if (_hBuffer.IsInvalid)
        {
            throw new Exception("Failed to open console buffer");
        }
    }

    public static void WriteAt(short x, short y, string value)
    {
        int n = 0;
        WriteConsoleOutputCharacter(_hBuffer, value, value.Length, new Coord(x, y), ref n);
    }

    public static void SetAttribute(short x, short y, int length, short attr)
    {
        short[] attrAry = new short[length];
        for (int i =0;i<length;i++)
        {
            attrAry[i] = attr;
        }
        SetAttribute(x, y, length, attrAry);
    }

    public static void SetAttribute(short x, short y, int length, short[] attrs)
    {
        int n = 0;
        WriteConsoleOutputAttribute(_hBuffer, attrs, length, new Coord(x, y), ref n);
    }

    public static void ClearArea(short left, short top, short width, short height, char ch = ' ')
    {
        ClearArea(left, top, width, height, new CharInfo() { Char = new CharUnion() { UnicodeChar = ch } });
    }

    public static void ClearArea(short left, short top, short width, short height)
    {
        ClearArea(left, top, width, height, new CharInfo() { Char = new CharUnion() { AsciiChar = 32 } });
    }

    private static void ClearArea(short left, short top, short width, short height, CharInfo charAttr)
    {
        CharInfo[] buf = new CharInfo[width * height];
        for (int i = 0; i < buf.Length; ++i)
        {
            buf[i] = charAttr;
        }

        SmallRect rect = new SmallRect() { Left = left, Top = top, Right = (short)(left + width), Bottom = (short)(top + height) };
        WriteConsoleOutput(_hBuffer, buf,
          new Coord() { X = width, Y = height },
          new Coord() { X = 0, Y = 0 },
          ref rect);
    }


    [DllImport("kernel32.dll", SetLastError = true)]
    static extern SafeFileHandle GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteConsoleOutput(
      SafeFileHandle hConsoleOutput,
      CharInfo[] lpBuffer,
      Coord dwBufferSize,
      Coord dwBufferCoord,
      ref SmallRect lpWriteRegion);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteConsoleOutputCharacter(
      SafeFileHandle hConsoleOutput,
      string lpCharacter,
      int nLength,
      Coord dwWriteCoord,
      ref int lpumberOfCharsWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteConsoleOutputAttribute(
      SafeFileHandle hConsoleOutput,
      short[] lpAttributes,
      int nLength,
      Coord dwWriteCoord,
      ref int lpumberOfAttrsWritten);

    [StructLayout(LayoutKind.Sequential)]
    struct Coord
    {
        public short X;
        public short Y;

        public Coord(short X, short Y)
        {
            this.X = X;
            this.Y = Y;
        }
    };

    [StructLayout(LayoutKind.Explicit)]
    struct CharUnion
    {
        [FieldOffset(0)]
        public char UnicodeChar;
        [FieldOffset(0)]
        public byte AsciiChar;
    }

    [StructLayout(LayoutKind.Explicit)]
    struct CharInfo
    {
        [FieldOffset(0)]
        public CharUnion Char;
        [FieldOffset(2)]
        public short Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SmallRect
    {
        public short Left;
        public short Top;
        public short Right;
        public short Bottom;
    }
}
