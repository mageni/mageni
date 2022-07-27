###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_IIS_UrlScanFilter.nasl 10949 2018-08-14 09:36:21Z emoss $
#
# If IIS installed, Test over WMI if Microsoft Url scan filter is installed
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96025");
  script_version("$Revision: 10949 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Test if Microsoft Url scan filter is installed(win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"If IIS installed,
  test over WMI if Microsoft Url scan filter is installed:");

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

if(!OSVER || OSVER >< "none"){
    set_kb_item(name:"WMI/IIS_UrlScanFilter", value:"error");
    set_kb_item(name:"WMI/IIS_UrlScanFilter/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/IIS_UrlscanFilter", value:"error");
  set_kb_item(name:"WMI/IIS_UrlScanFilter/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

IISVER = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\InetStp", val_name:"MajorVersion");

if(!IISVER){
    set_kb_item(name:"WMI/IIS_UrlScanFilter", value:"None");
    set_kb_item(name:"WMI/IIS_UrlScanFilter/log", value:"IT-Grundschutz: IIS ist not installed");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
    exit(0);
}

windirpath = wmi_os_windir(handle:handle);

if (OSVER < 6){
  val01 = split(windirpath, sep:"|", keep:0);
  val02 = split(val01[4], sep:"\", keep:0);
  val03 = eregmatch(pattern:".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string:val02[1]);
  pathini = val02[0] + "\\" + val03[0] + "\\system32\\inetsrv\\urlscan\\urlscan.ini";
  pathdll = val02[0] + "\\" + val03[0] + "\\system32\\inetsrv\\urlscan\\urlscan.dll";
}
if (OSVER >= 6){
  val01 = split(windirpath, sep:'\n', keep:0);
  val02 = split(val01[1], sep:"\", keep:0);
  val03 = eregmatch(pattern:".*[A-Za-z0-9-_/./(/)!$%&=+#@~^]", string:val02[1]);
  pathini = val02[0] + "\\" + val03[0] + "\\system32\\inetsrv\\urlscan\\urlscan.ini";
  pathdll = val02[0] + "\\" + val03[0] + "\\system32\\inetsrv\\urlscan\\urlscan.dll";
}

fileExistini = wmi_file_check_file_exists(handle:handle, filePath:pathini);
fileExistdll = wmi_file_check_file_exists(handle:handle, filePath:pathdll);

if(fileExistini == "1" && fileExistdll == "1"){
  note = val02[0] + '\\' + val03[0] + '\\system32\\inetsrv\\urlscan\\urlscan.ini' + ';';
  note = note + val02[0] + '\\' + val03[0] + '\\system32\\inetsrv\\urlscan\\urlscan.dll' + ';';
}
else {
  note = "FALSE";
}

if(note)set_kb_item(name:"WMI/IIS_UrlScanFilter", value:note);
else set_kb_item(name:"WMI/IIS_UrlScanFilter", value:"None");

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

exit(0);
