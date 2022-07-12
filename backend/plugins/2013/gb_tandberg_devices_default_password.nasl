###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tandberg_devices_default_password.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Tandberg Devices Default Password
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103695");
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Tandberg Devices Default Password");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-04-10 12:01:48 +0100 (Wed, 10 Apr 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_tandberg_devices_detect.nasl");
  script_require_ports(23);
  script_mandatory_keys("host_is_tandberg_device");
  script_tag(name:"solution", value:"Change the password.");
  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"summary", value:"The remote Tandberg device has the default password 'TANDBERG'.");
  exit(0);
}

include("telnet_func.inc");

port = 23;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

buf = telnet_negotiate(socket:soc);

if("Password:" >!< buf)exit(0);

send(socket:soc, data:'TANDBERG\n');
recv = recv(socket:soc, length:512);

if("OK" >!< recv)exit(0);

send(socket:soc, data:'ifconfig\n');
recv = recv(socket:soc, length:512);

send(socket:soc, data:'exit\n');

if("HWaddr" >< recv && "Inet addr" >< recv) {

  security_message(port:port);
  exit(0);

}

exit(99);

