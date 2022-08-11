###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_blackboard_lc3000_default_pw.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Blackboard LC3000 Laundry Reader Default Telnet Password
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103843");
  script_version("$Revision: 13624 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Blackboard LC3000 Laundry Reader Default Telnet Password");

  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2013/10/28/290/");

  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-12-02 11:02:55 +0200 (Mon, 02 Dec 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/blackboard/lc3000/detected");

  script_tag(name:"impact", value:"Attackers can exploit these issues to gain unauthorized access to the
  affected device and perform certain administrative actions.");

  script_tag(name:"vuldetect", value:"Start a telnet session with the default password.");

  script_tag(name:"insight", value:"A user can login to the Telnet service using the default password
  'IPrdr4U'");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"summary", value:"The remote Blackboard LC3000 Laundry Reader is prone to a default
  credentials bypass vulnerability");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port(default:23);
banner = get_telnet_banner(port:port);
if(!banner || 'Blackboard LC3000' >!< banner)
  exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

recv = recv(socket:soc, length:1024);
if("Enter Password" >!< recv)exit(0);

send(socket:soc, data:'IPrdr4U\r\n');

recv = recv(socket:soc, length:1024);
close(soc);

if("showconfig" >< recv && "ipreboot" >< recv) {
  security_message(port:port);
  exit(0);
}

exit(99);