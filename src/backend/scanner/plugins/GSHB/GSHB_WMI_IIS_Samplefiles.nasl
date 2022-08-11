###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_IIS_Samplefiles.nasl 10949 2018-08-14 09:36:21Z emoss $
#
# IIS Samplefiles and Scripte (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.96008");
  script_version("$Revision: 10949 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IIS Samplefiles and Scripte (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"The script detects if IIS Samplefiles and Scripte are installed.");

  exit(0);
}

include("wmi_file.inc");
include("wmi_os.inc");
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


if(!OSVER || OSVER >< "none"){
    set_kb_item(name:"WMI/IIS-Samplefiles", value:"error");
    set_kb_item(name:"WMI/IIS-Samplefiles/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/IIS-Samplefiles", value:"error");
  set_kb_item(name:"WMI/IIS-Samplefiles/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

IISVER = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\InetStp", val_name:"MajorVersion");

if(!IISVER){
    set_kb_item(name:"WMI/IIS-Samplefiles", value:"off");
    set_kb_item(name:"WMI/IIS-Samplefiles/log", value:"IT-Grundschutz: No IIS installed, Test not needed!");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
    exit(0);
}

sysdirpath = wmi_os_sysdir(handle:handle);

ProgramDir = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion", key_name:"ProgramFilesDir (x86)");

if (!ProgramDir){
  ProgramDir = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion", key_name:"ProgramFilesDir");
}

val01 = split(ProgramDir, sep:"\", keep:0);

if (OSVER < 6)
{
  val11 = split(sysdirpath, sep:"|", keep:0);
  val12 = split(val11[4], sep:"\", keep:0);
  val13 = eregmatch(pattern:".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string:val12[2]);
  syspath = "\\" + val12[1] + "\\" + val13[0] + "\\";
}
else
{
  val11 = split(sysdirpath, sep:":", keep:0);
  val13 = eregmatch(pattern:".*[A-Za-z0-9-_///./(/)!$%&=+#@~^]", string:val11[1]);
  val13 = split(val13[0], sep:"\", keep:0);
  syspath = "\\" + val13[1] + "\\" + val13[2] + "\\";
}

filespec1 = "\\Inetpub\\iissamples\\";
filespec2 = "\\Inetpub\\iissamples\\sdk\\";
filespec3 = "\\Inetpub\\AdminScripts\\";
filespec4 = "\\" + val01[1] + "\\" + "Common Files\\System\\msadc\\Samples\\";
filespec5 = syspath + "inetsrv\\iisadmpwd\\";

r1 = wmi_file_filelist(handle:handle, dirPath:filespec1);
r2 = wmi_file_filelist(handle:handle, dirPath:filespec2);
r3 = wmi_file_filelist(handle:handle, dirPath:filespec3);
r4 = wmi_file_filelist(handle:handle, dirPath:filespec4);
r5 = wmi_file_filelist(handle:handle, dirPath:filespec5);

if( r1 || r2 || r3 || r4 || r5) {
   set_kb_item(name:"WMI/IIS-Samplefiles", value:"on");
   if (r1) set_kb_item(name:"WMI/IIS-Samplefiles/iissamples", value:"on");
   if (r2) set_kb_item(name:"WMI/IIS-Samplefiles/iissdk", value:"on");
   if (r3) set_kb_item(name:"WMI/IIS-Samplefiles/iisadminscripts", value:"on");
   if (r4) set_kb_item(name:"WMI/IIS-Samplefiles/iismsadc", value:"on");
   if (r5) set_kb_item(name:"WMI/IIS-Samplefiles/iissdmpwd", value:"on");
   } else { set_kb_item(name:"WMI/IIS-Samplefiles", value:"off");
}
wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

exit(0);
