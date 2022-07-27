###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_W2K3_ClientFunk.nasl 10949 2018-08-14 09:36:21Z emoss $
#
# Find Windows 2003 Client Funktionality over WMI (win)
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96018");
  script_version("$Revision: 10949 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Find Windows 2003 Client Funktionality over WMI (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"Find Windows 2003 Client Funktionality over WMI:

 NetMeeting

 OutlookExpress

 Windows Media Player");

  exit(0);
}

include("wmi_file.inc");
include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSNAME = get_kb_item("WMI/WMI_OSNAME");

if(!OSVER || OSVER >< "none"){
    set_kb_item(name:"WMI/Win2k3ClientFunktion", value:"error");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/NetMeeting", value:"error");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/OutlookExpress", value:"error");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/Mediaplayer", value:"error");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/Win2k3ClientFunktion", value:"error");
  set_kb_item(name:"WMI/Win2k3ClientFunktion/NetMeeting", value:"error");
  set_kb_item(name:"WMI/Win2k3ClientFunktion/OutlookExpress", value:"error");
  set_kb_item(name:"WMI/Win2k3ClientFunktion/Mediaplayer", value:"error");
  set_kb_item(name:"WMI/Win2k3ClientFunktion/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

if (OSVER != '5.2' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition'){
    set_kb_item(name:"WMI/Win2k3ClientFunktion", value:"inapplicable");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/NetMeeting", value:"inapplicable");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/OutlookExpress", value:"inapplicable");
    set_kb_item(name:"WMI/Win2k3ClientFunktion/Mediaplayer", value:"inapplicable");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
    exit(0);
}

ProgramDir = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion", key_name:"ProgramFilesDir (x86)");

if (!ProgramDir){
  ProgramDir = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion", key_name:"ProgramFilesDir");
}

val01 = split(ProgramDir, sep:"\", keep:0);
path = val01[0] + "\\" + val01[1] + "\\";

ExistNetMeeting = wmi_file_check_file_exists(handle:handle, filePath:path + "NetMeeting\\conf.exe"  );
if(ExistNetMeeting == "1"){
    ExistNetMeeting = val01[0] + "\" + val01[1] + "\" + "NetMeeting\conf.exe ;";
}

ExistOutlookExpress = wmi_file_check_file_exists(handle:handle, filePath:path + "Outlook Express\\msimn.exe"  );
if(ExistOutlookExpress == "1"){
    ExistOutlookExpress = val01[0] + "\" + val01[1] + "\" + "Outlook Express\msimn.exe ;";
}

ExistMediaplayer = wmi_file_check_file_exists(handle:handle, filePath:path + "Windows Media Player\\wmplayer.exe"  );
if(ExistMediaplayer == "1"){
    ExistMediaplayer = val01[0] + "\" + val01[1] + "\" + "Windows Media Player\wmplayer.exe ;";
}


if(ExistNetMeeting)set_kb_item(name:"WMI/Win2k3ClientFunktion/NetMeeting", value:ExistNetMeeting);
else set_kb_item(name:"WMI/Win2k3ClientFunktion/NetMeeting", value:"None");

if(ExistOutlookExpress)set_kb_item(name:"WMI/Win2k3ClientFunktion/OutlookExpress", value:ExistOutlookExpress);
else set_kb_item(name:"WMI/Win2k3ClientFunktion/OutlookExpress", value:"None");

if(ExistMediaplayer)set_kb_item(name:"WMI/Win2k3ClientFunktion/Mediaplayer", value:ExistMediaplayer);
else set_kb_item(name:"WMI/Win2k3ClientFunktion/Mediaplayer", value:"None");

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

exit(0);
