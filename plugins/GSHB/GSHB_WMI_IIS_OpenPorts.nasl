###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_IIS_OpenPorts.nasl 10628 2018-07-25 15:52:40Z cfischer $
#
# Test over WMI, if Microsoft IIS installed an list open Ports (win)
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
  script_oid("1.3.6.1.4.1.25623.1.0.96029");
  script_version("$Revision: 10628 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:52:40 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Test over WMI, if Microsoft IIS installed an list open Ports (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "secpod_open_tcp_ports.nasl");

  script_tag(name:"summary", value:"Test over WMI, if Microsoft IIS installed an list open Ports:");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("misc_func.inc");
include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

ports = get_all_tcp_ports_list();
OSVER = get_kb_item("WMI/WMI_OSVER");

if(!OSVER || OSVER >< "none"){
    set_kb_item(name:"WMI/IISandPorts", value:"error");
    set_kb_item(name:"WMI/IISandPorts/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/IISandPorts", value:"error");
  set_kb_item(name:"WMI/IISandPorts/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

IISVER = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\\Microsoft\\InetStp", val_name:"MajorVersion");

if(!IISVER){
    set_kb_item(name:"WMI/IISandPorts", value:"None");
    set_kb_item(name:"WMI/IISandPorts/log", value:"IT-Grundschutz: IIS ist not installed");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
    exit(0);
}

if(isnull(ports)){
    set_kb_item(name:"WMI/IISandPorts", value:"error");
    set_kb_item(name:"WMI/IISandPorts/log", value:"IT-Grundschutz: Not Ports detected, perhaps Port Scanner was not applied!");
    wmi_close(wmi_handle:handle);
    wmi_close(wmi_handle:handlereg);
exit(0);
}

portlist = "IIS Version " + IISVER + '|';

foreach port( ports ) {
  portlist = portlist + port + '|';
}

set_kb_item(name:"WMI/IISandPorts", value:portlist);
wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);
exit(0);
