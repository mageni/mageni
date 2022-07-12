###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_PasswdPolicie.nasl 10949 2018-08-14 09:36:21Z emoss $
#
# Read the Windows Password Policy over WMI (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
# Thomas Rotter<T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.96033");
  script_version("$Revision: 10949 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Read the Windows Password Policy over WMI (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_mandatory_keys("WMI/access_successful");

  script_tag(name:"summary", value:"This script reads the Windows Password Policy configuration over WMI.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("wmi_rsop.inc");
include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
passwd  = kb_smb_password();
domain  = kb_smb_domain();
if( domain ) usrname = domain + "\" + usrname;

OSVER = get_kb_item("WMI/WMI_OSVER");
WindowsDomainrole = get_kb_item("WMI/WMI_WindowsDomainrole");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/lockoutpolicy", value:"error");
  set_kb_item(name:"WMI/passwdpolicy", value:"error");
  set_kb_item(name:"WMI/passwdpolicy/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

#if(WindowsDomainrole == "4" || WindowsDomainrole == "5")
  handle = wmi_connect(host:host, username:usrname, password:passwd, ns:'root\\rsop\\computer');
#else
#  handle = wmi_connect_rsop(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/lockoutpolicy", value:"error");
  set_kb_item(name:"WMI/passwdpolicy", value:"error");
#  set_kb_item(name:"WMI/passwdpolicy/log", value:"wmi_connect_rsop: WMI Connect failed.");
  set_kb_item(name:"WMI/passwdpolicy/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

pwdList = wmi_rsop_passwdpolicy(handle);

if(pwdList != NULL)
{
  pwdList = split(pwdList, "\n", keep:0);
  for(i=1; i<max_index(pwdList); i++)
  {
    desc = split(pwdList[i], sep:"|", keep:0);
    if(desc != NULL){
      set_kb_item(name:"WMI/passwdpolicy/" + desc[4], value:desc[7]);
    }
  }
}
else
{
  set_kb_item(name:"WMI/passwdpolicy", value:"False");
}

lkList = wmi_rsop_lockoutpolicy(handle);
if(lkList != NULL)
{
  lkList = split(lkList, "\n", keep:0);
  for(i=1; i<max_index(lkList); i++)
  {
    desc = split(lkList[i], sep:"|", keep:0);
    if(desc != NULL){
      set_kb_item(name:"WMI/lockoutpolicy/" + desc[4], value:desc[7]);
    }
  }
}
else
{
  set_kb_item(name:"WMI/lockoutpolicy", value:"False");
}

if( OSVER >= "6.2" ){

  pinLogin = registry_get_dword( key:"SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions", item:"value", type:"HKLM");
  if( pinLogin || pinLogin == "0" ){
    set_kb_item(name:"WMI/passwdpolicy/pinLogin", value:pinLogin);
  }else{
    set_kb_item(name:"WMI/passwdpolicy/pinLogin", value:"None");
  }
}

wmi_close(wmi_handle:handle);

set_kb_item(name:"WMI/lockoutpolicy/stat", value:"ok");
set_kb_item(name:"WMI/passwdpolicy/stat", value:"ok");

exit(0);
