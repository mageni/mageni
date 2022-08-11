###############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_virii.nasl 12978 2019-01-08 14:15:07Z cfischer $
#
# The remote host is infected by a virus
#
# Authors:
# Tenable Network Security
# Modified by Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2005 Tenable Network Security
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80043");
  script_version("$Revision: 12978 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 15:15:07 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("The remote host is infected by a virus");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Tenable Network Security");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"solution", value:"See the URLs which will appear in the report.");

  script_tag(name:"summary", value:"This script checks for the presence of different virii on the remote
  host, by using the SMB credentials you provide the scanner with.");


  script_tag(name:"insight", value:"The following virii are checked:

  - W32/Badtrans-B

  - JS_GIGGER.A@mm

  - W32/Vote-A

  - W32/Vote-B

  - CodeRed

  - W32.Sircam.Worm@mm

  - W32.HLLW.Fizzer@mm

  - W32.Sobig.B@mm

  - W32.Sobig.E@mm

  - W32.Sobig.F@mm

  - W32.Sobig.C@mm

  - W32.Yaha.J@mm

  - W32.mimail.a@mm

  - W32.mimail.c@mm

  - W32.mimail.e@mm

  - W32.mimail.l@mm

  - W32.mimail.p@mm

  - W32.Welchia.Worm

  - W32.Randex.Worm

  - W32.Beagle.A

  - W32.Novarg.A

  - Vesser

  - NetSky.C

  - Doomran.a

  - Beagle.m

  - Beagle.j

  - Agobot.FO

  - NetSky.W

  - Sasser

  - W32.Wallon.A

  - W32.MyDoom.M

  - W32.MyDoom.AI

  - W32.MyDoom.AX

  - W32.Aimdes.B

  - W32.Aimdes.C

  - W32.ahker.D

  - Hackarmy.i

  - W32.Erkez.D/Zafi.d

  - Winser-A

  - Berbew.K

  - Hotword.b

  - W32.Backdoor.Ginwui.B

  - W32.Wargbot

  - W32.Randex.GEL

  - W32.Fujacks.B");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

local_var nname, url, key, item, exp;

if(!get_kb_item("SMB/WindowsVersion")){
 exit(0);
}

function check_reg(nname, url, key, item, exp)
{
  if(!registry_key_exists(key:key)){
    return 0;
  }

  value = registry_get_sz(item:item, key:key);
  if(!value)return 0;

  if(exp == NULL || tolower(exp) >< tolower(value))
  {
   report = string(
"The virus '", nname, "' is present on the remote host\n\n",
"Registry-Key checked '", key, "'\n",
"Registry-Item checked '", item, "'\n",
"Registry-Value exists '", value, "'\n",
"Registry-Value expected '", exp, "'\n",
"Solution: ", url);

  security_message(port:kb_smb_transport(), data:report);
 }
}

count = 0;
nname = NULL;

# http://www.infos3000.com/infosvirus/badtransb.htm
nname[count]    = "W32/Badtrans-B";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.badtrans.b@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
item[count]     = "kernel32";
exp[count]      = "kernel32.exe";

count++;
# http://www.infos3000.com/infosvirus/jsgiggera.htm
nname[count]    = "JS_GIGGER.A@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/js.gigger.a@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "NAV DefAlert";
exp[count]      = NULL;

count++;
# http://www.infos3000.com/infosvirus/vote%20a.htm
nname[count]    = "W32/Vote-A";
url[count]      = "http://www.sophos.com/virusinfo/analyses/w32vote-a.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "Norton.Thar";
exp[count]      = "zacker.vbs";

count++ ;
nname[count]    = "W32/Vote-B";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.vote.b@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "ZaCker";
exp[count]      = "DaLaL.vbs";

count++;

# http://www.infos3000.com/infosvirus/codered.htm
nname[count]    = "CodeRed";
url[count]      = "http://www.symantec.com/avcenter/venc/data/codered.worm.html";
key[count]      = "SYSTEM\CurrentControlSet\Services\W3SVC\Parameters";
item[count]     = "VirtualRootsVC";
exp[count]      = "c:\,,217";

count++;
# http://www.infos3000.com/infosvirus/w32sircam.htm
nname[count]    = "W32.Sircam.Worm@mm";
url[count]      = "http://www.symantec.com/avcenter/venc/data/w32.sircam.worm@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[count]     = "Driver32";
exp[count]      = "scam32.exe";

count++;
nname[count]    = "W32.HLLW.Fizzer@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.hllw.fizzer@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "SystemInit";
exp[count]      = "iservc.exe";

count++;
nname[count]    = "W32.Sobig.B@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.b@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "SystemTray";
exp[count]      = "msccn32.exe";

count++;
nname[count]    = "W32.Sobig.E@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.e@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "SSK Service";
exp[count]      = "winssk32.exe";

count++;
nname[count]    = "W32.Sobig.F@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.f@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "TrayX";
exp[count]      = "winppr32.exe";

count++;
nname[count]    = "W32.Sobig.C@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.sobig.c@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "System MScvb";
exp[count]      = "mscvb32.exe";

count++;
nname[count]    = "W32.Yaha.J@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.yaha.j@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "winreg";
exp[count]      = "winReg.exe";

count++;
nname[count]    = "W32.mimail.a@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.a@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "VideoDriver";
exp[count]      = "videodrv.exe";

count++;
nname[count]    = "W32.mimail.c@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.c@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "NetWatch32";
exp[count]      = "netwatch.exe";

count++;
nname[count]    = "W32.mimail.e@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.e@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "SystemLoad32";
exp[count]      = "sysload32.exe";

count++;
nname[count]    = "W32.mimail.l@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.l@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "France";
exp[count]      = "svchost.exe";

count++;
nname[count]    = "W32.mimail.p@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mimail.p@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "WinMgr32";
exp[count]      = "winmgr32.exe";

count++;
nname[count]    = "W32.Welchia.Worm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.welchia.worm.html";
key[count]      = "SYSTEM\CurrentControlSet\Services\RpcTftpd";
item[count]     = "ImagePath";
exp[count]      = "%System%\wins\svchost.exe";

count++;
nname[count]    = "W32.Randex.Worm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.b.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "superslut";
exp[count]      = "msslut32.exe";

count++;
nname[count]    = "W32.Randex.Worm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.c.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "Microsoft Netview";
exp[count]      = "gesfm32.exe";

count++;
nname[count]    = "W32.Randex.Worm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.d.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "mssyslanhelper";
exp[count]      = "msmsgri32.exe";

count++;
nname[count]    = "W32.Randex.Worm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.randex.d.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "mslanhelper";
exp[count]      = "msmsgri32.exe";

count++;
nname[count]    = "W32.Beagle.A";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.beagle.a@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "d3update.exe";
exp[count]      = "bbeagle.exe";

count++;
nname[count]    = "W32.Novarg.A";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.novarg.a@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "TaskMon";
exp[count]      = "taskmon.exe";

count++;
nname[count]    = "Vesser";
url[count]      = "http://www.f-secure.com/v-descs/vesser.shtml";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "KernelFaultChk";
exp[count]      = "sms.exe";

count++;
nname[count]    = "NetSky.C";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.netsky.c@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "ICQ Net";
exp[count]      = "winlogon.exe";

count++;
nname[count]    = "Doomran.a";
url[count]      = "http://es.trendmicro-europe.com/enterprise/security_info/ve_detail.php?Vname=WORM_DOOMRAN.A";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "Antimydoom";
exp[count]      = "PACKAGE.EXE";

count++;
nname[count]    = "Beagle.m";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.beagle.m@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "winupd.exe";
exp[count]      = "winupd.exe";

count++;
nname[count]    = "Beagle.j";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.beagle.j@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "ssate.exe";
exp[count]      = "irun4.exe";

count++;
nname[count]    = "Agobot.FO";
url[count]      = "http://www.f-secure.com/v-descs/agobot_fo.shtml";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "nVidia Chip4";
exp[count]      = "nvchip4.exe";

count++;
nname[count]    = "NetSky.W";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.netsky.w@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "NetDy";
exp[count]      = "VisualGuard.exe";

count++;
nname[count]    = "Sasser";
url[count]      = "http://www.lurhq.com/sasser.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "avserve.exe";
exp[count]      = "avserve.exe";

count++;
nname[count]    = "Sasser.C";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.sasser.c.worm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "avserve2.exe";
exp[count]      = "avserve2.exe";

count++;
nname[count]    = "W32.Wallon.A";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.wallon.a@mm.html";
key[count]      = "SOFTWARE\Microsoft\Internet Explorer\Extensions\{FE5A1910-F121-11d2-BE9E-01C04A7936B1}";
item[count]     = "Icon";
exp[count]      = NULL;

count++;
nname[count]    = "W32.MyDoom.M / W32.MyDoom.AX";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mydoom.ax@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "JavaVM";
exp[count]      = "JAVA.EXE";

count++;
nname[count]    = "W32.MyDoom.AI";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mydoom.ai@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "lsass";
exp[count]      = "lsasrv.exe";

count++;
nname[count]    = "W32.aimdes.b / W32.aimdes.c";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.aimdes.c@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "MsVBdll";
exp[count]      = "sys32dll.exe";

count++;
nname[count]    = "W32.ahker.d";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.ahker.d@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "Norton Auto-Protect";
exp[count]      = "ccApp.exe";

count++;
nname[count]    = "Trojan.Ascetic.C";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/trojan.ascetic.c.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "SystemBoot";
exp[count]      = "Help\services.exe";

count++;
nname[count]    = "W32.Alcra.A";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.alcra.a.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "p2pnetwork";
exp[count]      = "p2pnetwork.exe";

count++;
nname[count]    = "W32.Shelp";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.shelp.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "explorer";
exp[count]      = "explorer.exe";

# Submitted by David Maciejak
count++;
nname[count]    = "Winser-A";
url[count]      = "http://www.sophos.com/virusinfo/analyses/trojwinsera.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "nortonsantivirus";
exp[count]      = NULL;

count++;
nname[count]    = "Backdoor.Berbew.O";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/backdoor.berbew.o.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad";
item[count]     = "Web Event Logger";
exp[count]      = "{7CFBACFF-EE01-1231-ABDD-416592E5D639}";

count++;
nname[count]    = "w32.beagle.az";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.beagle.az@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "Sysformat";
exp[count]      = "sysformat.exe";

count++;
nname[count]    = "Hackarmy.i";
url[count]      = "http://www.zone-h.org/en/news/read/id=4404/";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "putil";
exp[count]      = "%windir%";

count++;
nname[count]    = "W32.Assiral@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.assiral@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "MS_LARISSA";
exp[count]      = "MS_LARISSA.exe";

count++;
nname[count]    = "Backdoor.Netshadow";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/backdoor.netshadow.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "Windows Logger";
exp[count]      = "winlog.exe";

count++;
nname[count]    = "W32.Ahker.E@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.ahker.e@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "Generic Host Process for Win32 Services";
exp[count]      = "bazzi.exe";

count++;
nname[count]    = "W32.Bropia.R";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.bropia.r.html";
key[count]      = "Microsoft\Windows\CurrentVersion\Run";
item[count]     = "Wins32 Online";
exp[count]      = "cfgpwnz.exe";

count++;
nname[count]    = "Trojan.Prevert";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/trojan.prevert.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "Service Controller";
exp[count]      = "%System%\service.exe";

count++;
nname[count]    = "W32.AllocUp.A";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.allocup.a.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = ".msfupdate";
exp[count]      = "%System%\msveup.exe";

count++;
nname[count]    = "W32.Kelvir.M";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.kelvir.m.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "LSASS32";
exp[count]      = "Isass32.exe";

count++;
nname[count]    = "VBS.Ypsan.B@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/vbs.ypsan.b@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "BootsCfg";
exp[count]      = "wscript.exe C:\WINDOWS\System\Back ups\Bkupinstall.vbs";

count++;
nname[count]    = "W32.Mytob.AA@mm";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.mytob.aa@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "MSN MESSENGER";
exp[count]      = "msnmsgs.exe";

count++;
nname[count]    = "Dialer.Asdplug";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/dialer.asdplug.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "ASDPLUGIN";
exp[count]      = "exe -N";

# Submitted by Jeff Adams
count++;
nname[count]    = "W32.Erkez.D/Zafi.D";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.erkez.d@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "Wxp4";
exp[count]      = "Norton Update";

count++;
nname[count]    = "W32.blackmal.e@mm (CME-24)";
url[count]      = "http://securityresponse.symantec.com/avcenter/venc/data/w32.blackmal.e@mm.html";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "ScanRegistry";
exp[count]      = "scanregw.exe";

count++;
nname[count]    = "W32.Randex.GEL";
url[count]      = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-081910-4849-99&tabid=2";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[count]     = "MS Java for Windows XP & NT";
exp[count]      = "javanet.exe";

count++;
nname[count]    = "W32.Randex.GEL";
url[count]      = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-081910-4849-99&tabid=2";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[count]     = "MS Java for Windows NT";
exp[count]      = "msjava.exe";

count++;
nname[count]    = "W32.Randex.GEL";
url[count]      = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-081910-4849-99&tabid=2";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[count]     = "MS Java Applets for Windows NT, ME & XP";
exp[count]      = "japaapplets.exe";

count++;
nname[count]    = "W32.Randex.GEL";
url[count]      = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-081910-4849-99";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices";
item[count]     = "Sun Java Console for Windows NT & XP";
exp[count]      = "jconsole.exe";

count++;
nname[count]    = "W32.Fujacks.A";
url[count]      = "http://www.symantec.com/enterprise/security_response/writeup.jsp?docid=2006-111415-0546-99";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "svohost";
exp[count]      = "FuckJacks.exe";

count++;
nname[count]    = "W32.Fujacks.B";
url[count]      = "http://www.symantec.com/security_response/writeup.jsp?docid=2006-112912-5601-99&tabid=2";
key[count]      = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
item[count]     = "svcshare";
exp[count]      = "spoclsv.exe";

for(xy=0;xy<=count;xy++)
{
  check_reg(nname:nname[xy], url:url[xy], key:key[xy], item:item[xy], exp:exp[xy]);
}

rootfile = smb_get_systemroot();
if ( ! rootfile ) exit(0);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\system.ini", string:rootfile);

off = 0;
resp = smb_read_file(file:file, share:share, offset:off, count:16384);
if(resp) {
  data = resp;
  while(strlen(resp) >= 16383)
  {
   off += strlen(resp);
   resp = smb_read_file(file:file, share:share, offset:off, count:16384);
   data += resp;
   if(strlen(data) > 1024 * 1024)break;
  }

 if("shell=explorer.exe load.exe -dontrunold" >< data)
 {
  report = string(
"The virus 'W32.Nimda.A@mm' is present on the remote host\n\n",
"Location checked: ", file, "\n\n",
"Solution: http://www.symantec.com/avcenter/venc/data/w32.nimda.a@mm.html");

  security_message(port:0, data:report);
 }
}

file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\goner.scr", string:rootfile);
handle = smb_read_file(file:file, share:share, offset:0, count:8);

if(handle)
{
 report = string(
"The virus 'W32.Goner.A@mm' is present on the remote host\n\n",
"Location checked: ", file, "\n\n",
"Solution: http://www.symantec.com/avcenter/venc/data/w32.goner.a@mm.html");
 security_message(port:0, data:report);
}

file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\winxp.exe", string:rootfile);
handle = smb_read_file(file:file, share:share, offset:0, count:8);

if(handle)
{
 report = string(
"The virus 'W32.Bable.AG@mm' is present on the remote host\n\n",
"Location checked: ", file, "\n\n",
"Solution: http://www.symantec.com/avcenter/venc/data/w32.beagle.ag@mm.html");
 security_message(port:0, data:report);
}

file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\dnkkq.dll", string:rootfile);
handle = smb_read_file(file:file, share:share, offset:0, count:8);

if(handle)
{
 report = string(
"The backdoor 'Backdoor.Berbew.K' is present on the remote host\n",
"Backdoor.Berbew.K is a backdoor which is designed to intercept the logins
and passwords used by the users of the remote host and send them to a
third party. It usually saves the gathered data in :
    System32\dnkkq.dll
    System32\datakkq32.dll
    System32\kkq32.dll

Delete these files and make sure to disable IE's Autofill feature for important
data (ie: online banking, credit cart numbers, etc...)

Solution: http://securityresponse.symantec.com/avcenter/venc/data/backdoor.berbew.k.html");
 security_message(port:0, data:report);
}

file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Swen1.dat", string:rootfile);
handle = smb_read_file(file:file, share:share, offset:0, count:8);

if(handle)
{
 report = string(
"The virus 'W32.Swen.A@mm' is present on the remote host\n\n",
"Location checked: ", file, "\n\n",
"Solution: http://securityresponse.symantec.com/avcenter/venc/data/w32.swen.a@mm.html");
 security_message(port:0, data:report);
}

# Submitted by Josh Zlatin-Amishav

file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:rootfile);
trojanname = raw_string(0xa0, 0x73, 0x76, 0x63, 0x68, 0x6F, 0x73, 0x74, 0x2E, 0x65,0x78, 0x65);

_file = string(file, "\\System32\\",trojanname);
handle = smb_read_file(file:_file, share:share, offset:0, count:8);

if (!handle) {
  _file = string(file, "\\System32\\_svchost.exe");
  handle = smb_read_file(file:_file, share:share, offset:0, count:8);
}

if (!handle) {
  _file = string(file, "\\System32\\Outlook Express");
  handle = smb_read_file(file:_file, share:share, offset:0, count:8);
}

if (!handle) {
  _file = string(file, "\\System32\\CFXP.DRV");
  handle = smb_read_file(file:_file, share:share, offset:0, count:8);
}

if (!handle) {
  _file = string(file, "\\System32\\CHJO.DRV");
  handle = smb_read_file(file:_file, share:share, offset:0, count:8);
}

if (!handle) {
  _file = string(file, "\\System32\\MMSYSTEM.DLX");
  handle = smb_read_file(file:_file, share:share, offset:0, count:8);
}

if (!handle) {
  _file = string(file, "\\System32\\OLECLI.DLX");
  handle = smb_read_file(file:_file, share:share, offset:0, count:8);
}

if (!handle) {
  _file = string(file, "\\System32\\Windll.dlx");
  handle = smb_read_file(file:_file, share:share, offset:0, count:8);
}

if (!handle) {
  _file = string(file, "\\System32\\Activity.AVI");
  handle = smb_read_file(file:_file, share:share, offset:0, count:8);
}

if (!handle) {
  _file = string(file, "\\System32\\Upgrade.AVI");
  handle = smb_read_file(file:_file, share:share, offset:0, count:8);
}

if (!handle) {
  _file = string(file, "\\System32\\System.lst");
  handle = smb_read_file(file:_file, share:share, offset:0, count:8);
}

if (!handle) {
  _file = string(file, "\\System32\\PF30txt.dlx");
  handle = smb_read_file(file:_file, share:share, offset:0, count:8);
}

if(handle)
{
  report = string(
"The trojan 'hotword' is present on the remote host\n\n",
"Location checked: ", _file, "\n\n",
"See also : http://securityresponse.symantec.com/avcenter/venc/data/trojan.hotword.html\n",
"See also : http://securityresponse.symantec.com/avcenter/venc/data/trojan.rona.html\n",
"Solution:  Use latest anti-virus signatures to clean the machine.");
  security_message(port:0, data:report);
}

# Submitted by David Maciejak

sober = make_list("nonzipsr.noz",
"clonzips.ssc",
"clsobern.isc",
"sb2run.dii",
"winsend32.dal",
"winroot64.dal",
"zippedsr.piz",
"winexerun.dal",
"winmprot.dal",
"dgssxy.yoi",
"cvqaikxt.apk",
"sysmms32.lla",
"Odin-Anon.Ger");

foreach f (sober)
{
 file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\" + f, string:rootfile);
 handle = smb_read_file(file:file, share:share, offset:0, count:8);
 if(handle)
 {
  report = string(
"The virus 'Sober.i@mm' is present on the remote host\n\n",
"Location checked: ", file, "\n\n",
"Solution: http://securityresponse.symantec.com/avcenter/venc/data/w32.sober.i@mm.html");
  security_message(port:0, data:report);
  break;
 }
}

file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\wgareg.exe", string:rootfile);
handle = smb_read_file(file:file, share:share, offset:0, count:8);
if(handle)
{
 report = string(
"The virus 'W32.Wargbot@mm' is present on the remote host\n\n",
"Location checked: ", file, "\n\n",
"Solution: http://www.symantec.com/security_response/writeup.jsp?docid=2006-081312-3302-99");
 security_message(port:0, data:report);
}

# Submitted by Josh Zlatin-Amishav

foreach f (make_list("zsydll.dll", "zsyhide.dll"))
{
 file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\" + f, string:rootfile);
 handle = smb_read_file(file:file, share:share, offset:0, count:8);
 if(handle)
 {
   report = string(
   "The backdoor 'W32.Backdoor.Ginwui.B' is present on the remote host\n\n",
   "Location checked: ", file, "\n\n",
   "See also : http://securityresponse.symantec.com/avcenter/venc/data/backdoor.ginwui.b.html\n",
   "Solution:  Use latest anti-virus signatures to clean the machine.");
   security_message(port:0, data:report);
   break;
 }
}

exit(0);
