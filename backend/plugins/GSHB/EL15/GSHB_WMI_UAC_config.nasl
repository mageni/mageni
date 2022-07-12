###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_UAC_config.nasl 10628 2018-07-25 15:52:40Z cfischer $
#
# Read the config of the User Account Control feature over WMI (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.96046");
  script_version("$Revision: 10628 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:52:40 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-01-15 16:20:21 +0100 (Fri, 15 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Read the config of the User Account Control feature over WMI");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_tag(name:"summary", value:"Read the config of the User Account Control feature over WMI.");
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
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/UAC", value:"error");
  set_kb_item(name:"WMI/UAC/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/UAC", value:"error");
  set_kb_item(name:"WMI/UAC/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

if(OSVER  <  "6.0"){
  set_kb_item(name:"WMI/UAC", value:"prevista");
  wmi_close(wmi_handle:handle);
  exit(0);
}

FilterAdministratorToken = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"FilterAdministratorToken");
ConsentPromptBehaviorAdmin = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"ConsentPromptBehaviorAdmin");
ConsentPromptBehaviorUser = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"ConsentPromptBehaviorUser");
EnableInstallerDetection = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"EnableInstallerDetection");
ValidateAdminCodeSignatures = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"ValidateAdminCodeSignatures");
EnableLUA = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"EnableLUA");
PromptOnSecureDesktop = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"PromptOnSecureDesktop");
EnableVirtualization = wmi_reg_get_dword_val(wmi_handle:handle, key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"EnableVirtualization");

if(FilterAdministratorToken == "0") FilterAdministratorToken = "0";
if(ConsentPromptBehaviorAdmin == "0") ConsentPromptBehaviorAdmin = "0";
if(ConsentPromptBehaviorUser == "0") ConsentPromptBehaviorUser = "0";
if(EnableInstallerDetection == "0") EnableInstallerDetection = "0";
if(ValidateAdminCodeSignatures == "0") ValidateAdminCodeSignatures = "0";
if(EnableLUA == "0") EnableLUA = "0";
if(PromptOnSecureDesktop == "0") PromptOnSecureDesktop = "0";
if(EnableVirtualization == "0") EnableVirtualization = "0";


set_kb_item(name:"WMI/FilterAdministratorToken", value:FilterAdministratorToken);
set_kb_item(name:"WMI/ConsentPromptBehaviorAdmin", value:ConsentPromptBehaviorAdmin);
set_kb_item(name:"WMI/ConsentPromptBehaviorUser", value:ConsentPromptBehaviorUser);
set_kb_item(name:"WMI/EnableInstallerDetection", value:EnableInstallerDetection);
set_kb_item(name:"WMI/ValidateAdminCodeSignatures", value:ValidateAdminCodeSignatures);
set_kb_item(name:"WMI/EnableLUA", value:EnableLUA);
set_kb_item(name:"WMI/PromptOnSecureDesktop", value:PromptOnSecureDesktop);
set_kb_item(name:"WMI/EnableVirtualization", value:EnableVirtualization);
set_kb_item(name:"WMI/UAC", value:"success");
wmi_close(wmi_handle:handle);
exit(0);

