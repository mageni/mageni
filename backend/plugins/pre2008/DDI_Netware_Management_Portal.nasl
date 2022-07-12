# OpenVAS Vulnerability Test
# Description: Unprotected Netware Management Portal
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2001 Digital Defense Inc.
# Copyright (C) 2001 H D Moore <hdmoore@digitaldefense.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.10826");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Unprotected Netware Management Portal");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Digital Defense Inc.");
  script_family("General");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8008);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Disable this service if it is not in use or block connections to
  this server on TCP ports 8008 and 8009.");

  script_tag(name:"summary", value:"The Netware Management Portal software is running on this machine.");

  script_tag(name:"impact", value:"The Portal allows anyone to view the current server configuration and
  locate other Portal servers on the network. It is possible to browse the server's filesystem by requesting
  the volume in the URL. However, a valid user account is needed to do so.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8008); #nb: ssl version sometimes on port 8009

res = http_get_cache(item:"/", port:port);
if(res && "NetWare Server" >< res) {
  security_message(port:port);
  exit(0);
}

exit(99);