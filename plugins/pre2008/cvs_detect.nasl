# OpenVAS Vulnerability Test
# $Id: cvs_detect.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: A CVS pserver is running
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10051");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("A CVS pserver is running");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/cvspserver");

  script_tag(name:"solution", value:"Block those ports from outside communication.");

  script_tag(name:"summary", value:"A CVS (Concurrent Versions System) server is installed, and it is configured
  to have its own password file, or use that of the system. This service starts as a daemon, listening on port
  TCP:port.");

  script_tag(name:"impact", value:"Knowing that a CVS server is present on the system gives attackers
  additional information about the system, such as that this is a
  UNIX based system, and maybe a starting point for further attacks.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service(default:2401, proto:"cvspserver");
soc = open_sock_tcp(port);
if(!soc)
  exit(0);

senddata = string("\r\n\r\n");
send(socket:soc, data:senddata);
recvdata = recv_line(socket:soc, length:1000);
close(soc);

if(recvdata && "cvs" >< recvdata) {
  security_message(port:port);
  exit(0);
}

exit(99);