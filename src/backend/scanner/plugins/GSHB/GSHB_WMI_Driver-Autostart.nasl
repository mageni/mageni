###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_Driver-Autostart.nasl 11349 2018-09-12 07:56:57Z cfischer $
#
# Driver Autoinstall (Windows)
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.109000");
  script_version("$Revision: 11349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 09:56:57 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-06-21 10:43:24 +0200 (Wed, 21 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Autoinstall drivers (Windows)");
  script_tag(name:"summary", value:"The script detects if driver autoinstall is disabled.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");

  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl");

  exit(0);
}

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
  set_kb_item(name:"WMI/Driver_Autoinstall", value:"error");
  set_kb_item(name:"WMI/Driver_Autoinstall/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/Driver_Autoinstall", value:"error");
  set_kb_item(name:"WMI/Driver_Autoinstall/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

DRIVER_INSTALL = wmi_reg_enum_value(wmi_handle:handle, key:"HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions");

if(!DRIVER_INSTALL){
  log_message(port:0, proto: "IT-Grundschutz", data:"Registry Path not found.");
  set_kb_item(name:"WMI/Driver_Autoinstall", value:"error");
  wmi_close(wmi_handle:handle);
  exit(0);
}else if ("DenyUnspecified" >!< DRIVER_INSTALL || "AllowAdminInstall" >!< DRIVER_INSTALL){
  log_message(port:0, proto: "IT-Grundschutz", data:"Registry Value not found.");
  set_kb_item(name:"WMI/Driver_Autoinstall", value:"error");
  wmi_close(wmi_handle:handle);
  exit(0);
}

driver_auto_install = wmi_reg_get_dword_val(wmi_handle:handle, key:"HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions", val_name:"DenyUnspecified");
allow_admin_install = wmi_reg_get_dword_val(wmi_handle:handle, key:"HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions", val_name:"AllowAdminInstall");

if(driver_auto_install == "1"){
  set_kb_item(name:"WMI/Driver_Autoinstall", value:"off");
}

if(driver_auto_install == "0"){
  set_kb_item(name:"WMI/Driver_Autoinstall", value:"on");
}

if(allow_admin_install == "1"){
  set_kb_item(name:"WMI/AllowAdminInstall", value:"on");
}

if(allow_admin_install == "0"){
  set_kb_item(name:"WMI/AllowAdminInstall", value:"off");
}

wmi_close(wmi_handle:handle);

exit(0);
