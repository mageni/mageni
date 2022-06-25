# OpenVAS Vulnerability Test
# $Id: bugbear_b_1080.nasl 13541 2019-02-08 13:21:52Z cfischer $
# Description: Bugbear.B worm
#
# Authors:
# Tenable Network Security
#
# Copyright:
# Copyright (C) 2003 Tenable Network Security
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11733");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Bugbear.B worm");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Tenable Network Security");
  script_family("Malware");
  script_require_ports(1080);
  script_dependencies("find_service.nasl");

  script_xref(name:"URL", value:"http://www.symantec.com/avcenter/venc/data/w32.bugbear.b@mm.removal.tool.html");

  script_tag(name:"solution", value:"- Use an Anti-Virus package to remove it.

  - Close your Windows shares

  - See the references for a removal tool.");

  script_tag(name:"summary", value:"BugBear.B backdoor is listening on this port.");

  script_tag(name:"impact", value:"An attacker may connect to it to retrieve secret
  information, e.g. passwords or credit card numbers.");

  script_tag(name:"insight", value:"The BugBear.B worm includes a key logger and can stop
  antivirus or personal firewall software. It propagates itself through email and open
  Windows shares.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

# bugbear.b is bound to port 1080. It sends data which seems to
# be host-specific when it receives the letter "p"

port = 1080;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(0);

send(socket:soc, data:"p");
r = recv(socket: soc, length: 308);
close(soc);
if(!strlen(r))exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);
send(socket: soc, data: "x");
r2 = recv(socket: soc, length: 308);
if(strlen(r2)) { exit(0); }
close(soc);

if(strlen(r) > 10 )
{
  security_message(port:port);
  register_service(port:port, proto:"bugbear_b");
  exit(0);
}