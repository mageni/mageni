###############################################################################
# OpenVAS Vulnerability Test
# $Id: trojan_horses.nasl 12057 2018-10-24 12:23:19Z cfischer $
#
# Trojan horses
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# References:
# From: "kai takashi" <rst@coders.com>
# Organization: takashi industries
# To: bugtraq@securityfocus.com
# Subject: Remote Shell Trojan: Threat, Origin and the Solution
# Date: Sun, 9 Sep 2001 14:40:27 +0300
# CC: incidents@securityfocus.com, focus-virus@securityfocus.com, vulnwatch@vulnwatch.org, contribute@linuxsecurity.org
#
# Date: Mon, 10 Mar 2003 01:54:12 -0500
# From: "Russ" <Russ.Cooper@RC.ON.CA>
# Subject: Alert: New Worm - W32/Deloder on TCP445
# To: NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#
# http://vil.nai.com/vil/content/v_100128.htm

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11157");
  script_version("$Revision: 12057 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 14:23:19 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Trojan horses");
  # Make sure we run after all service detection plugins
  # Otherwise, the list of dependencies would be too long
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Malware");
  script_dependencies("PC_anywhere_tcp.nasl", "SHN_discard.nasl", "X.nasl", "apcnisd_detect.nasl", "alcatel_backdoor_switch.nasl",
                      "asip-status.nasl", "auth_enabled.nasl", "bugbear.nasl", "cifs445.nasl", "dcetest.nasl", "dns_server.nasl",
                      "echo.nasl", "find_service1.nasl", "find_service2.nasl", "external_svc_ident.nasl", "mldonkey_telnet.nasl",
                      "mssqlserver_detect.nasl", "mysql_version.nasl", "nessus_detect.nasl", "qmtp_detect.nasl", "radmin_detect.nasl",
                      "secpod_rpc_portmap_tcp.nasl", "rpcinfo.nasl", "rsh.nasl", "socks.nasl", "telnet.nasl", "xtel_detect.nasl",
                      "xtelw_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/unknown");
  script_mandatory_keys("Host/runs_windows");

  script_tag(name:"solution", value:"If a trojan horse is running, run a good antivirus scanner.");

  script_tag(name:"summary", value:"An unknown service runs on this port. It is sometimes opened by Trojan horses.
  Unless you know for sure what is behind it, you'd better check your system.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("host_details.inc");

# This list comes from:
# http://www.sans.org/newlook/resources/IDFAQ/oddports.htm
# http://www.simovits.com/trojans/trojans.html
# http://www.bekkoame.ne.jp/~s_ita/port/port1-99.html
# and some antivirus web sites
#
trojanlist = "
UDP 1 Socket de Troie
TCP 2 Death
TCP 8 Nugache
TCP 15 B2
TCP 20 Senna Spy FTP server, Randex
TCP 21 Back Construction, Blade Runner, Cattivik FTP Server, CC Invader, Dark FTP, Deep Throat, Doly Trojan, Fore, FreddyK, Invisible FTP, Juggernaut 42, Larva, MBT, MotIv FTP, Net Administrator, Ramen, RTB 666, Senna Spy FTP server, The Flu, Traitor 21, WebEx, WinCrash, Malpayo, W32.Mytob, W32.Bobax, W32.Loxbot
TCP 22 Adore sshd, Shaft
TCP 23 ADM worm, Dagonit, Fire HacKer, MindControl, My Very Own trojan, Prosiak, RTB 666, Telnet Pro, Tiny Telnet Server - TTS, Truva Atl, Delf, Wingate
TCP 25 Ajan, Antigen, Bancos, Barok, BSE, Chimo, Email Password Sender - EPS, EPS II, Gip, Gris, Happy99, Hpteam mail, Hybris, I love you, Kuang2, Magic Horse, MBT (Mail Bombing Trojan), Mitglieder, Moscow Email trojan, Naebi, NewApt worm, ProMail trojan, Rustock, Shtirlitz, Stealth, Stukach, Tapiras, Terminator, WinPC, WinSpy, W32.Beagle, W32.HLLP.Sality
TCP 26 W32.Netsky
TCP 30 Agent 40421
TCP 31 Agent 31, Hackers Paradise, Masters Paradise
TCP 34 Fxsvc
TCP 37 Dimi, W32.Sober
TCP 39 SubSARI, Upfudoor
TCP 41 Deep Throat, Foreplay, Reduced Foreplay
TCP 42 W32.Dasher
TCP 44 Arctic
TCP 48 DRAT
TCP 50 DRAT
TCP 53 ADM worm, Civcat, Esteems, Lion, W32.Spybot, W32.Dasher
TCP 58 DMSetup
TCP 59 DMSetup, Sdbot
TCP 69 BackGate, Evala, W32.Evala.Worm, W32.Mockbot
UDP 69 W32.Blaster.Worm, W32.Bolgi.Worm, W32.Cycle, W32.Zotob
TCP 70 W32.Evala.Worm
TCP 79 CDK, Firehotcker
TCP 80 711 trojan (Seven Eleven), AckCmd, Back End, Back Orifice 2000 Plug-Ins, Cafeini, CGI Backdoor, Executor, God Message, God Message 4 Creator, Hooker, IISworm, MTX, NCX, Noob, Ramen, Reverse WWW Tunnel Backdoor, RingZero, RTB 666, Seeker, WAN Remote, Web Server CT, WebDownloader, Mydoom, Xeory, Zombam, W32.Yaha, Ketch, Mydoom, W32.Welchia,W32.HLLW.Doomjuice, W32.HLLW.Heycheck, W32.Gaobot, W32.HLLW.Polybot, W32.Beagle, W32.Spybot, Mindos, Hexem, Eaghouse, Tabela, W32.Ifbo, W32.Pinkton, W32.Tdiserv, W32.Bobax, W32.Theals, Banito, W32.Lile, Darkmoon, Bifrose, Lodear, Civcat, Muquest, W32.Feebs, Bebshell, Hesive
UDP 80 W32.Beagle, W32.Bobax
TCP 81 RemoConChubo, Bagle.bb, Beagle.AV, Xeory
UDP 81 W32.Beagle
TCP 82 W32.Netsky
TCP 88 PWSteal.Likmet
TCP 99 Hidden Port, Mandragore, NCX, Gnuman
TCP 101 Udps.10
TCP 110 Bancos, Civcat, ProMail trojan
TCP 113 Invisible Identd Daemon, Kazimas, Randex, W32.Korgo, W32.Spybot, W32.Mydoom, W32.Linkbot, W32.Bofra
TCP 119 Happy99, Horrortel
TCP 121 Attack Bot, God Message, JammerKillah
TCP 122 Upfudoor
TCP 123 Net Controller, Madfind
TCP 125 Fox
TCP 133 Farnaz
#TCP 135 Femot, W32.Blaster.Worm,W32.HLLW.Gaobot, W32.Yaha, W32.Francette.Worm,W32.Cissi, W32.Welchia, W32.HLLW.Polybot, W32.Kibuv.Worm, W32.Explet, W32.Lovgate, W32.Spybot, W32.Maslan, W32.Mytob, W32.Kassbot, W32.Reatle, Secefa, W32.Kiman
TCP 137 Chode
UDP 137 Femot, Msinit, Qaz
TCP 138 Chode
UDP 138 W32.Spybot
UDP 139 W32.Spybot
#TCP 139 Chode, God Message worm, Msinit, Netlog, Network, Qaz, Sadmind, SMB Relay, W32.HLLW.Deborms, W32.HLLW.Moega, W32.Yaha,W32.Cissi, W32.Reidana, W32.Licum, W32.Spybot, W32.Kiman
TCP 142 NetTaxi
TCP 145 W32.Spybot
TCP 146 Infector
UDP 146 Infector
TCP 166 NokNok
TCP 170 A-trojan
TCP 190 Netdevil.15
TCP 256 SpBot
TCP 321 W32.Looksky
TCP 334 Backage
TCP 335 HLLW.Nautic
TCP 382 W32.Rotor
TCP 411 Backage
TCP 420 Breach, Incognito, W32.Kibuv.Worm
TCP 421 TCP Wrappers trojan
TCP 443 Tabdim, W32.Kelvir, Civcat, W32.Kiman
TCP 445 W32.HLLW.Gaobot, W32.HLLW.Lioten, W32.HLLW.Deloder, W32.Slackor, W32.HLLW.Nebiwo, W32.HLLW.Moega, W32.HLLW.Deborms, W32.Yaha, Randex, W32.Bolgi.Worm,W32.Cissi, W32.Welchia, W32.HLLW.Polybot, W32.Sasser, W32.Cycle, W32.Bobax, W32.Kibuv.Worm, W32.Korgo, W32.Explet, Otinet, W32.Scane, W32.Aizu Rtkit, W32.Spybot, W32.Janx, Netdepix, W32.Wallz, W32.Mytob, W32.Ifbo, W32.Reatle, W32.Zotob, Secefa, W32.Kiman
TCP 449 ierk8243, Krei
TCP 452 Ompnmagic
TCP 455 Fatal Connections
TCP 456 Hackers Paradise
TCP 511 T0rn Rootkit
#TCP 513 Grlogin
TCP 514 RPC Backdoor
#TCP 515 lpdw0rm, Ramen
TCP 531 Net666, Rasmin
TCP 555 711 trojan (Seven Eleven), Ini-Killer , Net Administrator, Phase Zero, Phase-0, Stealth Spy
TCP 559 Solufina, Domwis
TCP 600 Sadmind
TCP 605 Secret Service
TCP 661 NokNok
TCP 665 W32.Netsky
TCP 666 Attack FTP, Back Construction, BLA trojan, Cain & Abel, Checkesp, lpdw0rm, NokNok, Satans Back Door - SBD, ServU, Shadow Phyre, Sixca, th3r1pp3rz (= Therippers), Microkos, FTP_Ana.C, Futro,  W32.Dreffort
TCP 667 SniperNet
TCP 669 DP trojan
TCP 692 GayOL
TCP 701 Marotob
TCP 707 Welchia
TCP 777 AimSpy, NetCrack, Undetected, TDS.SE
TCP 778 NetCrack
TCP 808 WinHole
TCP 829 Uzbet
# Hayu only attacks 211.159.93.0 - 211.159.93.255
# TCP 887 Huayu
TCP 890 Dsklite
TCP 901 NetDevil (control), Netdevil.15
TCP 902 NetDevil (keystrokes)
TCP 903 NetDevil (file transfer)
TCP 905 NetDevil.B
TCP 911 Dark Shadow, NetCrack
TCP 956 Crat
TCP 961 ierk8243
TCP 999 Chat power, Deep Throat, Foreplay, Reduced Foreplay, WinSatan
TCP 1000 Connecter, Der Spaeher / Der Spaeher, Direct Connection, Nibu
TCP 1001 Der Spaeher / Der Spaeher, Le Guardien, Silencer, WTheef, WebEx, Wortbot, Ghoice.12, Nibu, W32.Dumaru, Wortbot
TCP 1005 Theef
TCP 1008 Lion
TCP 1010 Doly Trojan
TCP 1011 Doly Trojan, Augudoor, Fatroj
TCP 1012 Doly Trojan, Urat.b
TCP 1015 Doly Trojan
TCP 1016 Doly Trojan
TCP 1020 Vampire
TCP 1021 Webus
TCP 1022 W32.Sasser
TCP 1023 W32.Sasser
TCP 1024 Jade, Latinus, NetSpy, Remote Administration Tool - RAT [no 2], Lingosky, Randex, W32.Mydoom
TCP 1025 ABCHlp, Fraggle Rock, md5 Backdoor, NetSpy, Remote Storm, Lala.B, 32.Spybot, W32.Dasher, W32.Kiman
UDP 1025 Remote Storm
TCP 1027 ABCHlp
# Lixy listens on 1029-1084
TCP 1029 Lixy, W32.Kipis, W32.Kobot
TCP 1030 Lixy
TCP 1031 Xanadu,Lixy
TCP 1032 Lixy
TCP 1033 Lixy
TCP 1034 Lixy, Mydoom.M, Zincite.A, Systsec, W32.Zindos
TCP 1035 Multidropper, Lixy, Sedepex
TCP 1039 Gapin
TCP 1040 Medias, Sedepex
TCP 1042 BLA trojan, Lixy
UDP 1042 BLA trojan, Lixy
TCP 1045 Rasmin, Lixy
TCP 1049 /sbin/initd, Lixy
TCP 1050 MiniCommand, Lixy
TCP 1051 W32.Kassbot
TCP 1052 W32.Reatle
TCP 1053 The Thief
TCP 1054 AckCmd, Lixy
TCP 1080 SubSeven 2.2, WinHole, Beagle, Mydoom, Lixy, Bugbear, Webus.C, W32.HLLW.Deadhat
TCP 1081 WinHole, Lixy, Zagaban
TCP 1082 WinHole, Lixy
TCP 1083 WinHole, Lixy
TCP 1084 Lixy
TCP 1088 Webus
TCP 1090 Xtreme
TCP 1092 Lovgate
TCP 1095 Remote Administration Tool - RAT
TCP 1097 Remote Administration Tool - RAT
TCP 1098 Remote Administration Tool - RAT
TCP 1099 Blood Fest Evolution, Remote Administration Tool - RAT
TCP 1100 Double-Take
# hacktel opens 15 ports!
TCP 1101 Hatckel
TCP 1102 Hatckel
TCP 1103 Hatckel
TCP 1104 Hatckel
UDP 1104 RexxRave
TCP 1105 Hatckel, Double-Take
TCP 1106 Hatckel
TCP 1107 Hatckel
TCP 1108 Hatckel
TCP 1109 Hatckel
TCP 1110 Hatckel
TCP 1111 Hatckel, AIMVision, Ultor, W32.Suclove
TCP 1112 Hatckel
TCP 1113 Hatckel
TCP 1114 Hatckel
TCP 1115 Hatckel
TCP 1117 W32.Zotob
TCP 1145 CHCP
TCP 1149 Lala
UDP 1149 Lala
TCP 1150 Orion
TCP 1151 Orion
TCP 1155 W32.Reatle
TCP 1170 Psyber Stream Server - PSS, Streaming Audio Server, Voice
TCP 1174 DaCryptic
TCP 1180 Unin68
TCP 1192 Lovgate.A, Lovgate.B, Lovgate.C
UDP 1200 NoBackO
UDP 1201 NoBackO
TCP 1201 actx
TCP 1207 SoftWAR
TCP 1208 Infector
TCP 1212 Kaos
TCP 1218 Feardoor
TCP 1219 Feardoor
TCP 1220 Beagle mass mailer
TCP 1234 SubSeven Java client, Ultors Trojan, Beagle (later variants)
TCP 1243 BackDoor-G, SubSeven, SubSeven Apocalypse, Tiles
TCP 1245 VooDoo Doll
TCP 1250 Explet.A
TCP 1255 Scarab
TCP 1256 Project nEXT, RexxRave
TCP 1269 Matrix
TCP 1272 The Matrix
TCP 1309 Jittar
TCP 1313 NETrojan
TCP 1337 Shadyshell, OptixPro.11.b
TCP 1338 Millennium Worm
TCP 1349 Bo dll
TCP 1386 Dagger
TCP 1394 Backdoor G-1, GoFriller
TCP 1409 Brakkeshell, IRC.Bifrut
TCP 1427 W32.Spybot
TCP 1433 W32.Spybot
TCP 1434 W32.SQLExp.Worm, W32.Spybot
UDP 1434 W32.Gaobot, W32.Kelvir, W32.Spybot, W32.Kiman
TCP 1441 Remote Storm
TCP 1444 Homutex
TCP 1491 W32.Spybot
TCP 1492 FTP99CMP
TCP 1524 Trinoo
TCP 1533 Miffice, Scanboot
TCP 1534 W32.Bizex
TCP 1568 Remote Hack
TCP 1600 Direct Connection, Shivka-Burka
TCP 1639 W32.Mydoom, W32.Bofra
TCP 1640 W32.Bofra
TCP 1700 NetHasp, Udps.10
TCP 1703 Exploiter
TCP 1749 Aureate, Gaobot.CPX
TCP 1751 W32.Loxbot
TCP 1772 NetControle
UDP 1772 NetControle
TCP 1777 Scarab
TCP 1807 SpySender
TCP 1826 Glacier
TCP 1863 W32.Mytob, Bifrose
TCP 1871 Serpa
TCP 1877 Lala
UDP 1877 Lala
TCP 1879 W32.Zori
TCP 1906 Verify
TCP 1907 Verify
TCP 1919 FTP.Casus
TCP 1966 Fake FTP
TCP 1969 OpC BO
TCP 1971 Bifrose
TCP 1973 Sonic
TCP 1981 Bowl, Shockrave
TCP 1987 Ciadoor.B
TCP 1988 W32.Kipis
TCP 1991 PitFall
TCP 1999 Back Door, Bifrose, SubSeven, TransScout
TCP 2000 Der Spaeher / Der Spaeher, Esteems, Insane Network, Last 2000, Remote Explorer 2000, Senna Spy Trojan Generator, Feardoor, Fearic, CNK.A
UDP 2000 Fearic
TCP 2001 Der Spaeher / Der Spaeher, Trojan Cow, OICQSer.165, OICQSer.17
TCP 2002 Singu, Slapper, W32.Beagle
TCP 2004 OICQSer.165, OICQSer.17
TCP 2005 OICQSer.165, OICQSer.17, Sequel, W32.Reatle
TCP 2006 W32.Jalabed
TCP 2007 OICQSer.165, OICQSer.17
TCP 2008 OICQSer.165, OICQSer.17
TCP 2009 OICQSer.165, OICQSer.17
TCP 2010 OICQSer.165, OICQSer.17
TCP 2011 OICQSer.165, OICQSer.17
TCP 2012 OICQSer.165, OICQSer.17
TCP 2014 OICQSer.17
TCP 2018 Fizzer
TCP 2019 Fizzer
TCP 2020 Fizzer
TCP 2021 Fizzer
TCP 2023 Ripper Pro
TCP 2041 Korgo
TCP 2050 PWSteal.Ldpinch
TCP 2060 OptixPro.12.b
TCP 2066 DLSw
TCP 2080 WinHole, Curdeal, Tjserv
TCP 2090 Expjan
TCP 2094 W32.Mytob, W32.Opanki
TCP 2115 Bugs
UDP 2130 Mini Backlash
TCP 2140 The Invasor
UDP 2140 Deep Throat, Foreplay, Reduced Foreplay
TCP 2155 Illusion Mailer
TCP 2189 Delf
TCP 2255 Nirvana
TCP 2281 HLLW.Nautic
TCP 2283 Hvl RAT, Nibu, W32.Dumaru
TCP 2300 Xplorer
TCP 2311 Studio 54
TCP 2330 IRC Contact
TCP 2331 IRC Contact
TCP 2332 IRC Contact
TCP 2333 IRC Contact
TCP 2334 IRC Contact
TCP 2335 IRC Contact
TCP 2336 IRC Contact
TCP 2337 IRC Contact
TCP 2338 IRC Contact
TCP 2339 IRC Contact, Voice Spy
UDP 2339 Voice Spy
TCP 2345 Doly Trojan
TCP 2400 Portd
TCP 2414 Shania
TCP 2425 Madfind
TCP 2442 W32.Spybot, W32.Kelvir
TCP 2444 Delf
TCP 2525 Berbew
TCP 2626 Delf
TCP 2527 Zvrop
TCP 2535 W32.Beagle
TCP 2555 Lion, T0rn Rootkit
TCP 2556 Beagle worm (later variants)
TCP 2565 Striker trojan
TCP 2583 WinCrash
TCP 2589 Dagger
TCP 2600 Digital RootBeer
TCP 2688 IRC.Aladinz.P
TCP 2699 Jittar
TCP 2700 actx
TCP 2702 Black Diver
TCP 2707 Bigfoot
TCP 2716 The Prayer
TCP 2745 Beagle worm (later variants)
TCP 2766 W32.HLLW.Deadhat
TCP 2773 SubSeven, SubSeven 2.1 Gold
TCP 2774 SubSeven, SubSeven 2.1 Gold
TCP 2784 Sdbot
TCP 2801 Phineas Phucker
TCP 2817 W32.Mytob
TCP 2929 Konik
UDP 2989 Remote Administration Tool - RAT, Brador.A
TCP 3000 FirstClass, InetSpy, Remote Shut, Kutex, W32.Mimail
TCP 3024 WinCrash
TCP 3028 Wortbot
TCP 3030 Slao, W32.Mytob
TCP 3031 Microspy
TCP 3067 Korgo
TCP 3127 MyDoom - Virus, W32.Mockbot, W32.Solame
TCP 3128 Reverse WWW Tunnel Backdoor, RingZero, MyDoom, W32.HLLW.Deadhat
TCP 3129 Masters Paradise
TCP 3131 SubSARI, Slao
TCP 3150 The Invasor
UDP 3150 Deep Throat, Foreplay, Reduced Foreplay, Mini Backlas
TCP 3172 W32.HLLW.Doomjuice
TCP 3195 IRC.Whisper
TCP 3232 Slao
TCP 3333 Slao
TCP 3355 Hogle
TCP 3256 W32.HLLW.Dax
TCP 3264 Smother
TCP 3306 Nemog, W32.Spybot
TCP 3330 Randex,Roxy
TCP 3331 Randex,Roxy
TCP 3332 Randex,Roxy, W32.Cycle
TCP 3333 W32.Bratle, W32.Zotob
TCP 3334 W32.Mytob
TCP 3351 W32.Reatle
TCP 3355 Hogle
TCP 3385 W32.Mytob
TCP 3388 Mitglieder
TCP 3398 PWSteal.Bancos
TCP 3410 Optix, W32.Mockbot
TCP 3422 IRC.Aladinz
TCP 3434 Slao
TCP 3436 Netjoe
TCP 3437 Netjoe
TCP 3456 Terror trojan, Fearic
UDP 3456 Fearic
TCP 3459 Eclipse 2000, Sanctuary
TCP 3515 W32.Spybot
TCP 3527 Zvrop
TCP 3547 Amitis.B
TCP 3700 Portal of Doom - POD
TCP 3737 Helios
TCP 3742 W32.Mytob
TCP 3777 PsychWard
TCP 3791 Total Solar Eclypse
# Roxy.B is a proxy HTTP server?
TCP 3800 Roxy.B
TCP 3801 Total Solar Eclypse, Roxy.B
TCP 3802 Roxy.B
TCP 4000 Connect-Back Backdoor, Skydance, Qiwei
UDP 4000 W32.Witty
TCP 4001 OptixPro.13.C
TCP 4092 WinCrash
TCP 4095 W32.Randex
TCP 4123 W32.Bratle
TCP 4128 RCServ
TCP 4191 Sdbot
TCP 4225 SilentSpy
TCP 4242 Nemog, Virtual Hacking Machine - VHM
TCP 4267 Lala
UDP 4267 Lala
TCP 4300 Smokodoor
TCP 4321 BoBo
TCP 4367 W32.Spybot
TCP 4432 Acidoor
TCP 4433 Acidoor
TCP 4444 CrackDown, Prosiak, Swift Remote, MS Blast, W32.Mockbot, W32.HLLW.Donk, W32.Reidana
TCP 4488 Event Horizon
TCP 4495 Berbew
TCP 4500 HLLW.Tufas
TCP 4512 W32.Mytob
TCP 4523 Celine
TCP 4527 Zvrop
TCP 4545 Internal Revise
TCP 4564 W32.Spybot
TCP 4567 File Nail
TCP 4590 ICQ Trojan
TCP 4627 Lala
TCP 4646 Nemog
TCP 4654 W32.Spybot
TCP 4653 Cero
TCP 4661 Nemog, Gamqowi
TCP 4666 Mneah
TCP 4751 Beagle worm (later variants), Mitglieder
TCP 4820 Tuxder
TCP 4888 W32.Opanki
TCP 4891 W32.Mytob
TCP 4899 W32.Rahack
TCP 4912 Mirab (direct control)
TCP 4950 ICQ Trogen (Lm)
TCP 4999 Malpayo, Ripjac
TCP 5000 Back Door Setup, BioNet Lite, Blazer5, Bubbel, ICKiller, Ra1d, Socket de Troie, Mytob.HH, Raid, W32.Bobax, Trojan.Webus, W32.Mytob
TCP 5001 Back Door Setup, Socket de Troie, Higuy
TCP 5002 cd00r, Linux Rootkit IV (4), Shaft, W32.Spybot
TCP 5003 W32.Spybot
TCP 5005 Aladino
TCP 5010 Solo
TCP 5011 One of the Last Trojans - OOTLT, One of the Last Trojans - OOTLT  modified
TCP 5025 WM Remote KeyLogger
TCP 5031 Net Metropolitan
TCP 5032 Net Metropolitan
TCP 5050 Roxrat.10
TCP 5111 Korgo
TCP 5135 FTP_Bmail
TCP 5136 Toob.A
TCP 5151 Optix
TCP 5180 Peeper
TCP 5232 Lateda, W32.Mytob, W32.Spybot
TCP 5277 WinJank
TCP 5300 W32.Kibuv.Worm
TCP 5321 Firehotcker
TCP 5326 Snowdoor
TCP 5328 Fxdoor, Snowdoor
TCP 5333 Backage, NetDemon
TCP 5343 wCrat - WC Remote Administration Tool
TCP 5373 Gluber.B
TCP 5400 Back Construction, Blade Runner
TCP 5401 Back Construction, Blade Runner, Mneah
TCP 5402 Back Construction, Blade Runner, Mneah
TCP 5418 DarkSky.B
TCP 5419 DarkSky.B
TCP 5424 W32.Mydoom
TCP 5425 W32.Mydoom
TCP 5426 W32.Mydoom
TCP 5467 W32.Kobot
UDP 5503 RST (Remote Shell Trojan)
TCP 5512 Illusion Mailer
TCP 5534 The Flu
TCP 5544 W32.Zotob
TCP 5550 Xtcp
TCP 5553 XLog
TCP 5554 Sasser backdoor, W32.Dabber
TCP 5555 ServeMe, Sysbug, OptixPro.14, Hale
TCP 5556 BO Facil
TCP 5557 BO Facil
TCP 5558 Easyserv
TCP 5569 Robo-Hack
TCP 5599 Mitglieder
TCP 5637 PC Crasher
TCP 5638 PC Crasher
TCP 5662 W32.Fanbot
TCP 5665 Kipis.B
TCP 5679 HLLW.Nautic
TCP 5695 Assassin.D
TCP 5732 W32.Bolgi.Worm
TCP 5742 WinCrash
TCP 5748 Ranck
TCP 5760 Portmap Remote Root Linux Exploit
TCP 5800 BackDoor-ARG, Evivinc
TCP 5802 Y3K RAT
TCP 5873 SubSeven 2.2
TCP 5880 Y3K RAT
TCP 5882 Y3K RAT, Y3KRat.14
UDP 5882 Y3K RAT
TCP 5884 Y3KRat.14
UDP 5888 Y3K RAT, Y3KRat.14
TCP 5889 Y3K RAT, Y3KRat.14
TCP 5900 Evivinc
TCP 5969 Sparta.C
TCP 6000 Lovgate, The Thing
TCP 6006 Bad Blood
TCP 6050 ARCserv
TCP 6051 Zdemon, SysXXX
TCP 6060 W32.Lovgate, W32.Spybot
TCP 6129 W32.Mockbot
TCP 6187 Tilser
TCP 6267 Darksky, GWGirl
TCP 6272 Secret Service
TCP 6351 Hale
TCP 6384 W32.HLLW.Gaobot
TCP 6394 W32.Spybot
TCP 6400 The Thing
TCP 6430 Mirab (file transfer)
TCP 6556 W32.Toxbot
TCP 6564 Sdbot
TCP 6565 Nemog
TCP 6595 Assassin.C
TCP 6631 Sdbot
TCP 6660 W32.Spybot
TCP 6661 TEMan, Weia-Meia
TCP 6663 W32.Mytob
TCP 6664 Futro, W32.Zotob
TCP 6665 Futro
TCP 6666 Dark Connection Inside, NetBus worm, Beasty, W32.HLLW.Warpigs, BAT.Boohoo.Worm, Foobot
TCP 6667 Dark FTP, EGO, Maniac rootkit, Moses, ScheduleAgent, SubSeven, Subseven 2.1.4 DefCon 8, The Thing (modified), Trinity, WinSatan, Deftcode, Spigot.C, W32.HLLW.Gaobot, IrcContact, Deftcode, IRC.Flood, W32.HLLW.Nool, W32.HLLW.Warpigs, W32.HLLW.Studd, W32.Cissi, W32.Mimail W32.Opasa, Sdbot, W32.Korgo, Hacarmy, W32.Mota, W32.Spybot, Alnica, W32.Mydoom, Maxload, W32.Bofra, Lateda, W32.Protoride, W32.Blatic, Mindos, W32.Wallz, W32.Bropia, W32.Randex, W32.Mytob, W32.Stubbot, W32.Linkbot, W32.Zotob, W32.Ruland, IRC.Litebot, Kaiten
TCP 6669 Host Control, Vampire
TCP 6670 BackWeb Server, Deep Throat, Foreplay or Reduced Foreplay, WinNuke eXtreame
TCP 6673 W32.Mytob
TCP 6697 Feardoor
TCP 6711 BackDoor-G, SubSARI, SubSeven , VP Killer, Kilo, Softshell
TCP 6712 Funny trojan, SubSeven
TCP 6713 SubSeven
TCP 6718 Kilo
TCP 6723 Mstream
TCP 6754 Mapsy
TCP 6767 UandMe
TCP 6771 Deep Throat, Foreplay, Reduced Foreplay
TCP 6776 2000 Cracks, BackDoor-G, SubSeven , VP Killer
TCP 6777 Bagle/Beagle worm (1st version), W32.Gaobot
TCP 6789 W32.Netsky
TCP 6811 Softshell
UDP 6838 Mstream
TCP 6868 Darkmoon
TCP 6883 Delta Source DarkStar (??)
TCP 6912 Shit Heep
TCP 6939 Indoctrination
TCP 6967 Diagcfg
TCP 6969 2000 Cracks, Danton, GateCrasher, IRC 3, Net Controller, Priority, Armageddon.B, Assassin.B, Khaos, Sparta.B, Robi, Ratega, Floodnet
TCP 6970 GateCrasher
TCP 7000 BAT.Boohoo.Worm, Exploit Translation Server, Kazimas, Remote Grab, SubSeven, SubSeven 2.1 Gold, W32.Gaobot, Spyboter, W32.Mydoom,
W32.Mytob
TCP 7001 Freak88, Freak2k, NetSnooper Gold
TCP 7043 W32.Spybot
TCP 7080 Haxdoor
TCP 7119 Massaker
TCP 7158 Lohoboyshik
TCP 7215 SubSeven, SubSeven 2.1 Gold
TCP 7222 Plupii
TCP 7273 Xibo
TCP 7300 NetMonitor
TCP 7301 NetMonitor
TCP 7306 NetMonitor
TCP 7307 NetMonitor, Remote Process Monitor
TCP 7308 NetMonitor, X Spy
TCP 7329 Netshadow
TCP 7410 Phoenix
TCP 7424 Host Control
UDP 7424 Host Control
TCP 7441 MeteorShell
TCP 7555 Plupii
TCP 7597 Qaz
TCP 7614 GRM
TCP 7626 Binghe, Glacier, Hyne
TCP 7673 Neodurk
TCP 7677 Neodurk
TCP 7714 Berbew, BKDR_BERBEW.A
TCP 7718 Glacier
TCP 7745 W32.Mytob
TCP 7777 God Message, The Thing (modified), Tini, Darkmoon
TCP 7789 Back Door Setup, ICKiller, Mozilla
TCP 7811 RemoteSOB
TCP 7823 Amitis.B
TCP 7826 Oblivion
TCP 7891 The ReVeNgEr
TCP 7896 Futh
TCP 7897 Futh
TCP 7955 W32.Kibuv
TCP 7983 Mstream
TCP 7999 W32.Mytob
TCP 8000 W32.Gaobot, W32.Spybot, W32.Mytob
TCP 8008 Haxdoor
TCP 8012 Ptakks.B
TCP 8051 Somali.A
TCP 8066 W32.Gaobot
TCP 8076 W32.Spybot, W32.Mytob
TCP 8080 Brown Orifice, Generic backdoor, RemoConChubo, Reverse WWW Tunnel Backdoor, RingZero, MyDoom, Nemog, Webus, W32.Spybot, Feutel, W32.Mytob, W32.Picrate, W32.Kelvir, W32.Opanki, Haxdoor, W32.Zotob, Tjserv, W32.Botter, W32.Looksky, Ryknos, Naninf, Hesive
TCP 8081 W32.Bufei, Danmec
TCP 8088 Hesive
TCP 8090 Asniffer (v1)
TCP 8126 W32.Pejaybot, W32.Spybot, W32.Kelvir
TCP 8172 W32.Zotob
TCP 8173 Zebroxy
TCP 8181 W32.Erkez
TCP 8190 WW32.Reatle
TCP 8311 Mxsender
TCP 8379 Binghe
UDP 8379 Binghe
TCP 8520 W32.Socay.Worm
TCP 8546 Berbew, BKDR_BERBEW.A
TCP 8563 Bozori.B, W32.Zotob
TCP 8594 Bozori.A
TCP 8595 W32.Zotob
TCP 8685 Unin68
TCP 8719 WinShell.50
TCP 8787 Back Orifice 2000
TCP 8800 W32.Noomy
TCP 8811 Monator, Fearic
UDP 8811 Fearic
TCP 8812 FraggleRock Lite
TCP 8848 Binghe
TCP 8866 Beagle worm (2nd version)
TCP 8881 W32.Mytob
TCP 8885 W32.Reatle
TCP 8888 Zotob.A, OptixPro.10.b, W32.Axatak
TCP 8889 W32.Axatak
TCP 8900 W32.Mytob
TCP 8961 Pears
TCP 8988 BacHack
TCP 8989 Rcon, Recon, Xcon
TCP 9000 DevilRobber.A, Netministrator, W32.Randex, W32.Mytob, W32.Esbot
TCP 9010 Tumag
TCP 9030 Beagle.BY
TCP 9035 Beagle.CK/CL
TCP 9040 Mitglieder
TCP 9059 W32.Esbot
TCP 9124 Fox
TCP 9125 Nibu.I, Nibu.J, Nibu.N
TCP 9136 Sdbot
TCP 9148 HLLW.Nautic
UDP 9325 Mstream
TCP 9400 InCommand
TCP 9515 W32.Loxbot
TCP 9561 Crat
TCP 9604 W32.Kibuv.Worm
TCP 9696 Kutex, Gholame
TCP 9697 Gholame
TCP 9777 StealthEye
TCP 9778 StealthEye
TCP 9832 W32.Mytob
TCP 9867 Sokeven
TCP 9870 Remote Computer Control Center
TCP 9871 Theef.B
TCP 9872 Portal of Doom - POD
TCP 9873 Portal of Doom - POD
TCP 9874 Portal of Doom - POD
TCP 9875 Portal of Doom - POD
TCP 9876 Cyber Attacker, Lolok, Rux
TCP 9878 TransScout
TCP 9898 Dabber Backdoor, CrashCool
TCP 9900 W32.HLLW.Gaobot
TCP 9955 W32.Reatle
TCP 9958 W32.Reatle
TCP 9989 Ini-Killer
TCP 9996 W32.Sasser
TCP 9999 The Prayer, Lateda.C, Beasty.I
TCP 10000 Dumaru.Y, OpwinTRojan
TCP 10001 Zdemon.126
TCP 10002 Zdemon.126
TCP 10005 OpwinTRojan
TCP 10008 Cheese worm, Lion
TCP 10011 Fatroj
TCP 10027 W32.Mytob
UDP 10067 Portal of Doom - POD
TCP 10080 MyDoom
TCP 10082 W32.Mytob
TCP 10085 Syphillis
TCP 10086 Syphillis
TCP 10087 Mytob.AQ, Mytob.BR, Mytob.BS
TCP 10089 Mytob.AR
TCP 10100 Control Total, GiFt trojan, Ranky
UDP 10100 Trojan.Dasda
TCP 10101 BrainSpy, Silencer
TCP 10102 Staprew
TCP 10103 Tuimer
UDP 10104 Lowtaper, Ranky
TCP 10113 Ranky
UDP 10167 Portal of Doom - POD
TCP 10168 Lovgate
TCP 10500 W32.Linkbot
TCP 10520 Acid Shivers
TCP 10528 Host Control
TCP 10607 Coma
UDP 10666 Ambush, Roxrat.12
TCP 10888 Webus.C
TCP 11000 Senna Spy Trojan Generator
TCP 11050 Host Control
TCP 11051 Host Control
TCP 11117 Mitglieder
TCP 11142 SubSeven.215
TCP 11223 Progenic trojan, Secret Agent
TCP 11311 Carufax
TCP 11831 Latinus, Antilam.g1/AED
TCP 12000 Satancrew, W32.Mytob
TCP 12065 Berbew
TCP 12076 Gjamer
TCP 12121 Balkart
TCP 12223 Hack'99 KeyLogger
TCP 12310 PreCursor
TCP 12321 Roxe.B
TCP 12345 Adore sshd, Ashley, cron / crontab, Fat Bitch trojan, GabanBus, icmp_client.c, icmp_pipe.c, Mypic , NetBus , NetBus Toy, NetBus worm, Pie Bill Gates, ValvNet, Whack Job, X-bill, Amitis.B
TCP 12346 Fat Bitch trojan, GabanBus, NetBus, X-bill, Wasil
TCP 12347 W32.Mytob
TCP 12348 BioNet
TCP 12349 BioNet, Webhead
TCP 12361 Whack-a-mole
TCP 12362 Whack-a-mole
TCP 12363 Whack-a-mole
TCP 12378 Gibe
UDP 12623 DUN Control
TCP 12624 ButtMan, Tubma
TCP 12631 Whack Job
TCP 12754 Mstream
TCP 12884 VagrNocker
TCP 13000 Senna Spy Trojan Generator, W32.Spybot
TCP 13010 BitchController, Hacker Brasil - HBR
TCP 13013 PsychWard
TCP 13014 PsychWard
TCP 13173 Amitis.B
TCP 13223 Hack'99 KeyLogger
TCP 13298 Theef.C
TCP 13473 Chupacabra
TCP 14247 Beagle/Mitglieder
TCP 14500 PC Invader
TCP 14501 PC Invader
TCP 14502 PC Invader
TCP 14503 PC Invader
TCP 14690 bitkeeper
TCP 14728 Zinx
TCP 15000 NetDemon
TCP 15092 Host Control
TCP 15104 Mstream
TCP 15348 Bionet.404
TCP 15382 SubZero
TCP 15432 Cyn
TCP 15739 Audiodoor
TCP 15858 CDK
TCP 16322 Lastdoor
TCP 16484 Mosucker
TCP 16660 Stacheldraht
TCP 16661 Haxdoor
TCP 16772 ICQ Revenge
TCP 16959 SubSeven, Subseven 2.1.4 DefCon 8
TCP 16969 Priority
TCP 16999 Stealer
TCP 17166 Mosaic
TCP 17300 Kuang2 the virus
TCP 17449 Kid Terror
TCP 17499 CrazzyNet
TCP 17500 CrazzyNet
TCP 17569 Infector
TCP 17593 AudioDoor
TCP 17771 Beagle/Mitglieder
TCP 17777 Nephron
TCP 17940 W32.Imav
TCP 18067 Mousey, W32.Esbot, W32.Mocbot
TCP 18354 Heplane
TCP 18667 Knark
UDP 18753 Shaft
TCP 18881 Beagle/Mitglieder
TCP 18888 LiquidAudio
TCP 18961 Haxdoor.B
TCP 19340 RemoteNC.B
TCP 19381 Watsoon.A
TCP 19703 Sonic
TCP 19864 ICQ Revenge
TCP 19907 W32.Zotob
TCP 19937 Gaster
TCP 20000 Millennium
TCP 20001 Insect, Millennium, Millennium (Lm)
TCP 20002 AcidkoR
TCP 20005 Mosucker
TCP 20023 VP Killer
TCP 20034 NetBus 2.0 Pro, NetBus 2.0 Pro Hidden, NetRex, Whack Job, Netbus.444051
TCP 20168 Lovgate
TCP 20192 Ranky
TCP 20203 Chupacabra
TCP 20226 AntiLam.20.Q
TCP 20331 BLA trojan
TCP 20432 Shaft
UDP 20433 Shaft
TCP 20742 Mitglieder
TCP 21211 W32.Dasher
TCP 21217 Asniffer (v2)
TCP 21544 GirlFriend, Kid Terror, Matrix, VagrNocker
TCP 21554 Exploiter, FreddyK, Kid Terror, Schwindler, Winsp00fer
TCP 21579 Breach
TCP 21957 Latinus
TCP 22222 Donald Dick, Prosiak, Ruler, RUX The TIc.K
TCP 22311 Simali
TCP 22783 Intruzzo
TCP 22784 Intruzzo, Renomb
TCP 22785 Intruzzo
TCP 23005 NetTrash, Olive, Oxon, Platrash
TCP 23006 NetTrash, Platrash
TCP 23023 Logged
TCP 23032 Amanda
TCP 23213 PowWow
TCP 23214 PowWow
TCP 23232 Berbew.E
TCP 23276 Smorph
TCP 23321 Konik
TCP 23422 W32.Beagle
TCP 23432 Asylum
TCP 23435 Framar, Volac, Frango
TCP 23456 Evil FTP, Ugly FTP, Whack Job
TCP 23476 Donald Dick
UDP 23476 Donald Dick
TCP 23477 Donald Dick, Smorph
TCP 23523 W32.Mytob
TCP 23560 Sparta
TCP 23666 Beasty.F
TCP 23777 InetSpy
TCP 24000 Infector
TCP 24289 Latinus
TCP 24300 W32.Randex
TCP 24681 Lowtaper
TCP 24759 Zinx
TCP 25025 Kodalo
TCP 25026 Kodalo
TCP 25044 Kodalo
TCP 25123 Goy'Z TroJan
TCP 25226 Delf.F
TCP 25555 FreddyK, Mitglieder
TCP 25685 MoonPie
TCP 25686 MoonPie
TCP 25857 Frethem.R
TCP 25982 MoonPie
UDP 26274 Delta Source, Trinoo
UDP 26418 W32.Mytob
TCP 26681 Voice Spy
TCP 27160 MoonPie
TCP 27328 Nibu.N
TCP 27374 Bad Blood, EGO, Fake SubSeven, Lion, Ramen, Seeker, SubSeven , SubSeven 2.1 Gold, Subseven 2.1.4 DefCon 8, SubSeven 2.2, SubSeven Muie, The Saint, Ttfloader, Webhead, Baste
TCP 27378 Delf
TCP 27379 Optix.04
UDP 27444 Trinoo
TCP 27551 Amitis
TCP 27573 SubSeven
TCP 27589 Assassin/SANISI.A
TCP 27665 Trinoo
TCP 27999 W32.Mytob
TCP 28253 Berbew
TCP 28431 Hack'a'Tack
TCP 28678 Exploiter
TCP 28876 Globe
TCP 28882 Mitglieder
TCP 29104 NetTrojan
TCP 29147 Sdbot
TCP 29292 BackGate, NTHack
TCP 29369 ovasOn
TCP 29559 Latinus, Antilam.g1/AED, Ducktoy
TCP 29891 The Unexplained
TCP 29999 AntiLam.20
TCP 30000 Infector
TCP 30001 ErrOr32, W32.Gaobot
TCP 30003 Lamers Death
TCP 30005 Backdoor JZ
TCP 30029 AOL trojan
TCP 30100 NetSphere
TCP 30101 NetSphere
TCP 30102 NetSphere
TCP 30103 NetSphere
UDP 30103 NetSphere
TCP 30133 NetSphere
TCP 30303 Socket de Troie
TCP 30700 Mantis
TCP 30947 Intruse
TCP 30999 Kuang2, Novacal
TCP 30722 W32.Esbot
TCP 30947 Intruse
TCP 30999 Kuang2, Novacal
TCP 31113 W32.Mytob
TCP 31221 Knark
TCP 31320 LittleWitch
UDP 31320 LittleWitch
TCP 31332 Grobodor
TCP 31335 Trinoo
TCP 31336 Bo Whack , Butt Funnel
TCP 31337 ADM worm, Back Fire, Back Orifice 1.20 patches, Back Orifice (Lm), Back Orifice russian, Baron Night, Beeone, bindshell, BO client, BO Facil, BO spy, BO2, cron / crontab, Freak88, Freak2k, Gummo, icmp_pipe.c,Linux Rootkit IV (4), Sm4ck, Sockdmini, Emcommander, W32.HLLW.Gool
UDP 31337 Back Orifice, Deep BO
TCP 31338 Back Orifice, Butt Funnel, NetSpy (DK)
UDP 31338 Deep BO, NetSpy (DK)
TCP 31339 NetSpy (DK)
TCP 31416 Lithium
TCP 31556 Zdemon, SysXXX
TCP 31557 Xanadu
TCP 31666 BOWhack
TCP 31693 Turkojan
TCP 31745 BuschTrommel
TCP 31785 Hack'a'Tack
TCP 31787 Hack'a'Tack
TCP 31788 Hack'a'Tack
UDP 31789 Hack'a'Tack
TCP 31790 Hack'a'Tack
UDP 31791 Hack'a'Tack
TCP 31792 Hack'a'Tack
TCP 32001 Donald Dick
TCP 32100 Peanut Brittle, Project nEXT
TCP 32121 Berbew.E
TCP 33333 Zotob.A
TCP 34123 DevilRobber.A
TCP 34321 DevilRobber.A
TCP 32418 Acid Battery
TCP 32440 Alets
TCP 32982 Wanukdoor.A
TCP 34522 DevilRobber.A
TCP 32791 Acropolis
TCP 33270 Trinity
TCP 33333 Blakharaz, Prosiak, Zotob.A, Selka, W32.Zotob
TCP 33567 Lion, T0rn Rootkit
TCP 33568 Lion, T0rn Rootkit
TCP 33577 PsychWard
TCP 33777 PsychWard
TCP 33911 Spirit 2000, Spirit 2001
TCP 34324 Big Gluck, TN
TCP 34330 W32.Myfip
TCP 34444 Donald Dick
UDP 34555 Trinoo (for Windows)
TCP 35000 Surgeon
UDP 35555 Trinoo (for Windows)
TCP 36183 Lifefournow
TCP 36794 BugBear
TCP 36963 Mytob.JI
TCP 37237 Mantis
TCP 37266 The Killer Trojan
TCP 37651 Yet Another Trojan - YAT
TCP 37737 Tixanbot
TCP 38741 CyberSpy
TCP 39122 Upfudoor
TCP 39507 Busters
TCP 39581 WinShell.50.b
TCP 39780 Nibu.O
TCP 39872 Cuhmap, Drator
TCP 40403 W32.Randex
TCP 40404 W32.Randex
TCP 40412 The Spy
TCP 40421 Agent 40421, Masters Paradise
TCP 40422 Masters Paradise
TCP 40423 Masters Paradise
TCP 40425 Masters Paradise
TCP 40426 Masters Paradise
TCP 41337 Storm
TCP 41666 Remote Boot Tool - RBT, Remote Boot Tool - RBT
TCP 41934 Ranky
TCP 42321 Ranky.E
TCP 43287 W32.Mytob
TCP 43958 IRC.Aladinz
TCP 44280 Amitis.B
TCP 44390 Amitis.B
TCP 44444 Prosiak, W32.Kibuv
TCP 44445 W32.Kibuv
TCP 44446 W32.Kibuv
TCP 44575 Exploiter
UDP 44767 School Bus
TCP 45559 Maniac rootkit
TCP 45672 Delf.F
TCP 45673 Acropolis
TCP 45836 W32.HLLW.Graps
TCP 47017 T0rn Rootkit
UDP 47262 Delta Source
TCP 47387 Amitis.B
TCP 47891 AntiLam.20
TCP 48004 Fraggle Rock
TCP 48006 Fraggle Rock, Fraggle
TCP 48094 Nibu.M
TCP 48522 Hale
TCP 49000 Fraggle Rock
TCP 49301 OnLine KeyLogger
TCP 49945 Danrit
TCP 50000 SubSARI
TCP 50005 Fulamer.25 (file transfer)
TCP 50021 OptixPro.11
TCP 50130 Enterprise
TCP 50305 Longnu
TCP 50505 Socket de Troie
TCP 50766 Fore, Schwindler
TCP 51234 Cyn
TCP 51966 Cafeini
TCP 51985 Remohak.16
TCP 52013 Graybird.C
TCP 52317 Acid Battery 2000
TCP 53001 Remote Windows Shutdown - RWS
TCP 53201 Backdoor.Ranck
TCP 53357 W95.Sma
TCP 53559 AntiLam.20.Q
TCP 54112 Ranky.F
TCP 54283 SubSeven , SubSeven 2.1 Gold
TCP 54312 Niovadoor
TCP 54320 Back Orifice 2000
TCP 54321 Back Orifice 2000, School Bus, Tenga.A
TCP 55000 Roxe
TCP 55165 File Manager trojan, File Manager trojan, WM Trojan Generator
TCP 55166 WM Trojan GeneratorTCP 57341 NetRaider
TCP 55168 Haxdoor
TCP 55665 Latinus.B
TCP 55666 Latinus.B
TCP 55808 Randex
TCP 56565 Osirdoor
TCP 57005 IRC.Cirebot
TCP 57123 Mprox
TCP 58008 Tron
TCP 58009 Tron
TCP 58339 Butt Funnel
TCP 58343 Prorat
TCP 58666 Redkod
TCP 59211 Ducktoy
TCP 60000 Deep Throat, Foreplay, Reduced Foreplay, Socket de Troie
TCP 60001 Trinity
TCP 60006 Fulamer.25 (direct control)
TCP 60008 Lion, T0rn Rootkit
TCP 60068 Xzip 6000068
TCP 60101 Stealer
TCP 60411 Connection
TCP 60552 Roxrat.10
TCP 61000 Mite
TCP 61001 Chimo
TCP 61002 Chimo
TCP 61003 Chimo
TCP 61137 W32.Mytob
TCP 61282 W32.Squirm@mm, W32.Pandem.B.Worm
TCP 61337 Nota
TCP 61348 Bunker-Hill
TCP 61466 TeleCommando
TCP 61603 Bunker-Hill
TCP 63000 W32.Gaobot
TCP 63001 W32.Gaobot
TCP 63117 Beasty
TCP 63485 Bunker-Hill
TCP 63809 Gaobot
TCP 64101 Taskman / Task Manager
TCP 64429 Amitis.B
TCP 64444 Sdbot
TCP 65000 Devil, Socket de Troie, Stacheldraht, Roxrat.12
TCP 65010 Roxrat.12
TCP 65111 Microkos
TCP 65390 Eclypse
TCP 65421 Jade
TCP 65432 The Traitor (= th3tr41t0r)
UDP 65432 The Traitor (= th3tr41t0r)
TCP 65475 W32.Gaobot
TCP 65528 W32.Spybot
TCP 65529 W32.Spybot
TCP 65530 Windows Mite
TCP 65534 /sbin/initd
TCP 65535 Adore worm, RC1 trojan, Sins
";

# Currently, we only check TCP trojan horses
port = get_unknown_port( nodefault:TRUE );

# I don't know any trojan horse that runs on top of SSL/TLS
t = get_port_transport(port);
if (t == ENCAPS_SSLv23 || t == ENCAPS_SSLv2 || t == ENCAPS_SSLv3 || t == ENCAPS_TLSv1 || t == ENCAPS_TLSv11 || t == ENCAPS_TLSv12) exit(0);

req = string("^TCP ", port, " ");
str = egrep(string:trojanlist, pattern: req);
if (! str) exit(0);

key = string("unknown/banner/", port);
banner = get_kb_item(key);

# If banner is void, no use to open the port: find_service already did the job
# MA 2005-10-11: however, find_service* may fail if this is a dynamic port or if the service was crashed by a test. So we check that the port is still open

soc = open_sock_tcp(port);
if (! soc) {
  debug_print('Connection refused on port ', port, '\n');
  exit(0);
}

if (! banner )
 banner = recv(socket: soc, length: 1024);

close(soc);

name = ereg_replace(string: str, pattern: req, replace: "");
name = ereg_replace(string: name, pattern: " *, *", replace: string("\n\t"));
m = string("An unknown service runs on this port. It is sometimes opened by this/these Trojan horse(s):\n\t", name,"\n");

if (banner)
  m = string(m, "Here is the service banner:\n", banner, "\n\n");
security_message(port: port, data: m);

exit(0);