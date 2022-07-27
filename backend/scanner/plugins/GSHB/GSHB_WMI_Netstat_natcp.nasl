###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_Netstat_natcp.nasl 10628 2018-07-25 15:52:40Z cfischer $
#
# Get Windows TCP Netstat over win_cmd_exec
#
# Authors:
# Thomas Rotter <Thomas.Rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.94251");
  script_version("$Revision: 10628 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:52:40 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-09-08 13:12:52 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get Windows TCP Netstat over win_cmd_exec");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("compliance_tests.nasl", "smb_login.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB", "SMB/password", "SMB/login");
  script_require_ports(139, 445);
  script_exclude_keys("SMB/samba");

  script_tag(name:"summary", value:"Get Windows TCP Netstat over win_cmd_exec");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");

if( kb_smb_is_samba() ) exit( 0 );
if( ! defined_func("win_cmd_exec") ) exit( 0 );

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
passwd = kb_smb_password();
if (domain){
  usrname = domain + '/' + usrname;
}

if(!host || !usrname || !passwd){
  set_kb_item(name:"GSHB/WMI/NETSTAT/log", value:"nocred");
  exit(0);
}

if(get_kb_item("win/lsc/disable_win_cmd_exec")){
  set_kb_item(name:"GSHB/WMI/NETSTAT/log", value:"win_cmd_exec manually disabled");
  exit(0);
}

a = "netstat.exe -na -p tcp";
b = "netstat.exe -na -p tcpv6";
vala = win_cmd_exec (cmd:a, password:passwd, username:usrname);
valb = win_cmd_exec (cmd:b, password:passwd, username:usrname);

report = vala + "\n" + valb;

set_kb_item(name:"GSHB/WMI/NETSTAT", value:report);
exit(0);
