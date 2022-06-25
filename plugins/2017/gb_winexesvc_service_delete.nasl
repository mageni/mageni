###############################################################################
# OpenVAS Vulnerability Test
#
# Remove deprecated Authenticated Scan supporting service
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.112041");
  script_version("2020-02-06T11:17:59+0000");
  script_tag(name:"last_modification", value:"2020-02-06 11:17:59 +0000 (Thu, 06 Feb 2020)");
  script_tag(name:"creation_date", value:"2017-09-15 08:40:00 +0200 (Fri, 15 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Remove deprecated Authenticated Scan supporting service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("toolcheck.nasl", "smb_registry_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_access", "Tools/Present/wmi");
  script_exclude_keys("win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"In the past, during an Authenticated Scan, it was sometimes necessary to deploy a
  service onto the target machine. As this method is deprecated now, the service is removed.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

if(get_kb_item("win/lsc/disable_win_cmd_exec"))
  exit(0);

username = kb_smb_login();
password = kb_smb_password();

if(!username)
  exit(0);

domain = kb_smb_domain();
if(domain)
  username = domain + "/" + username;

service  = "winexesvc";
command  = "sc query " + service;
response = win_cmd_exec(cmd:command, username:username, password:password);

if("RUNNING" >< response) {
  command  = "sc stop " + service;
  response = win_cmd_exec(cmd:command, username:username, password:password);
}

if("STOPPED" >< response) {
  command = "sc delete " + service;
  win_cmd_exec(cmd:command, username:username, password:password);
}

exit(0);
