# SIPlogSSH
multithreaded siplog viewer that can read siplogs from a file steam or built-in ssh terminal stream.
you can connect to a linux SIP server with the built-in SSH terminal and issue the command tcpdump -i any -nn -A -tttt port 5060. When SIPlogSSH sees a call the screen will change to a list of calls. You can toggle back to the terminal by pressing T and fro mthe terminal you can toggle the list of calls by entering @@@. You can issue ctrl-c in the terminal by entering +++ .

