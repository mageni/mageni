# OpenVAS Vulnerability Test
# Description: A CVS pserver is running
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2005 SecuriTeam
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
  script_version("2020-09-30T10:18:14+0000");
  script_tag(name:"last_modification", value:"2020-10-09 10:01:41 +0000 (Fri, 09 Oct 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("A CVS pserver is running");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/cvspserver");

  script_tag(name:"summary", value:"A CVS (Concurrent Versions System) server is installed, and it is configured
  to have its own password file, or use that of the system. This service starts as a daemon, listening on port
  TCP:port.");

  script_tag(name:"qod_type", value:"remote_banner");

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
  report = "A CVS server was detected on the target system.";
  log_message(data:report, port:port);
  exit(0);
}

exit(99);
