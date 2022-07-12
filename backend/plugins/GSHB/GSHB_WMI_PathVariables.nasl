###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_PathVariables.nasl 10949 2018-08-14 09:36:21Z emoss $
#
# Windows Path Variable over WMI (win)
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
  script_oid("1.3.6.1.4.1.25623.1.0.96032");
  script_version("$Revision: 10949 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Windows Path Variable over WMI (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"Read the Windows System Path Variables over WMI.");

  exit(0);
}

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
  set_kb_item(name:"WMI/WinPathVar", value:"error");
  set_kb_item(name:"WMI/WinPathVar/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handlereg){
  set_kb_item(name:"WMI/WinPathVar", value:"error");
  set_kb_item(name:"WMI/WinPathVar/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

PathVar = wmi_reg_get_ex_string_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", val_name:"Path");


if(!PathVar)
{
  handle = wmi_connect(host:host, username:usrname, password:passwd);
  OSWINDIR = get_kb_item("WMI/WMI_OSWINDIR");
  query = "select VariableValue from Win32_Environment WHERE Name = 'path'";
  PathVar = wmi_query(wmi_handle:handle, query:query);
  PathVar = split(PathVar, sep:"|", keep:0);
  PathVar = ereg_replace(pattern:'%SystemRoot%', string:PathVar[4], replace:OSWINDIR);
  PathVar = ereg_replace(pattern:'\n', string:PathVar, replace:'');

  wmi_close(wmi_handle:handle);

  if(!PathVar)PathVar = "None";
}


set_kb_item(name:"WMI/WinPathVar", value:PathVar);

wmi_close(wmi_handle:handlereg);

exit(0);
