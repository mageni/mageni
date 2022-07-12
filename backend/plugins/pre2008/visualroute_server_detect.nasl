# OpenVAS Vulnerability Test
# Description: VisualRoute Web Server Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10744");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("VisualRoute Web Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_family("General");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("VisualRoute/banner");
  script_require_ports("Services/www", 8000);

  script_tag(name:"solution", value:"Disable the VisualRoute web server, or block the web server's
  port number on your Firewall.");

  script_tag(name:"summary", value:"We detected the remote web server as being a VisualRoute web server.
  This server allows attackers to perform a traceroute to a third party's
  hosts without revealing themselves to the target of the traceroute.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:8000 );

banner = get_http_banner(port:port);
if(!banner)
  exit(0);

if(egrep(pattern:"^Server: VisualRoute (tm) ", string:banner)) {
  security_message(port:port);
  exit(0);
}

exit(99);