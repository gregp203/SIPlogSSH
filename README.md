# SIPlogSSH
multithreaded siplog viewer that can read siplogs from a file steam or built-in ssh terminal stream.
you can connect to a linux SIP server with the built-in SSH terminal and issue the command tcpdump -i any -nn -A -tttt port 5060 or tial -f a log file. Certain unix progams like VI, less and man do not work well with dumb terminals, and cnt be used reliably with this terminal. For this to work charactor and keyboard mapping would needed to done which exceeds the scope for the need of the termnial which is to get sip messages on the screen. When SIP messages are showing in the terminal press ctrl+t to see the list of calls.  
