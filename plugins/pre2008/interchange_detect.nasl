###############################################################################
# OpenVAS Vulnerability Test
# $Id: interchange_detect.nasl 10317 2018-06-25 14:09:46Z cfischer $
#
# redhat Interchange
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
###############################################################################

# Note: this service is *not* a web server, but it looks like it for
# find_service
# HEAD / HTTP/1.0	(the only request it seems to recognize)
# HTTP/1.0 200 OK
# Last-modified: [15/August/2002:17:41:40 +0200]
# Content-type: application/octet-stream
#
# GET / HTTP/1.0   (or anything else, even not HTTP: GROUMPF\r\n)
# HTTP/1.0 404 Not found
# Content-type: application/octet-stream
#
# / not a Interchange catalog or help file.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11128");
  script_version("$Revision: 10317 $");
  script_bugtraq_id(5453);
  script_tag(name:"last_modification", value:"$Date: 2018-06-25 16:09:46 +0200 (Mon, 25 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("redhat Interchange");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7786);

  script_tag(name:"solution", value:"Upgrade your software if necessary or configure it
  for 'Unix mode' communication only.");

  script_tag(name:"summary", value:"It seems that 'Red Hat Interchange' ecommerce and dynamic
  content management application is running in 'Inet' mode on this port.

  Versions 4.8.5 and earlier are flawed and may disclose
  contents of sensitive files to attackers.

  ** OpenVAS neither checked Interchange version nor tried
  ** to exploit the vulnerability");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");

port = get_http_port(default:7786);
host = http_host_name(port:port);

soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket: soc, data: string("OPENVAS / HTTP/1.0", "\r\n",
         "Host: ", host, "\r\n\r\n"));
r = recv(socket: soc, length: 1024);
close(soc);

if ("/ not a Interchange catalog or help file" >< r) log_message(port);
