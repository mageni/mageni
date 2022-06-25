###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_IPmux-2L_default_credentials.nasl 13636 2019-02-13 12:23:58Z cfischer $
#
# IPmux-2L TDM Pseudowire Access Gateway Default Credentials
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
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103860");
  script_version("$Revision: 13636 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 13:23:58 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-12-18 11:44:04 +0200 (Wed, 18 Dec 2013)");
  script_name("IPmux-2L TDM Pseudowire Access Gateway Default Credentials");

  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2013/12/17/ipmux-2l-tdm-pseudowire-access-gateway-default-credentials/");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/ipmux-2l/tdm/detected");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"summary", value:"The remote IPmux-2L TDM Pseudowire Access Gateway
  is prone to a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.

  It was possible to login as user 'SU' with password '1234'.");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port(default:23);
banner = get_telnet_banner(port:port);
if(!banner || "IPmux-2L" >!< banner)
  exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

buf = recv(socket:soc, length:4096);

if("IPmux-2L" >!< buf) {
  close(soc);
  exit(0);
}

send(socket:soc, data:'SU\r\n1234\r\n\r\n');

buf = recv(socket:soc, length:4096);
close(soc);

if("main menu" >< buf && "Inventory" >< buf && "Configuration" >< buf) {
  security_message(port:port);
  exit(0);
}

exit(99);