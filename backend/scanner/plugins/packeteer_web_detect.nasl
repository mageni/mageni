###############################################################################
# OpenVAS Vulnerability Test
# $Id: packeteer_web_detect.nasl 11407 2018-09-15 11:02:05Z cfischer $
#
# Packeteer/Bluecoat Web Management Interface Detection
#
# Authors:
# nnposter
#
# Copyright:
# Copyright (C) 2008 nnposter
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80031");
  script_version("$Revision: 11407 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:02:05 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Packeteer/Bluecoat Web Management Interface Detection");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (c) 2008 nnposter");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Packeteer Web Management Interface Detection.
  The script sends a connection request to the server and attempts to
  determine if the host is a Packeteer/Bluecoat PacketShaper from the reply.");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = get_http_port(default:80);

req = http_get(item:"/login.htm", port:port);
resp = http_send_recv(port:port, data:req);
if (!resp) exit(0);

server = egrep(pattern:"^Server: *httpd/1\.",string:resp,icase:TRUE);
cookie = egrep(pattern:"^Set-Cookie: *[^a-z0-9]PScfgstr=",string:resp,icase:TRUE);
if (!server || !cookie) exit(0);

if(!eregmatch(pattern:"PacketShaper Login</title>", string: resp, icase:TRUE))exit(0);
model = eregmatch(pattern:">PacketShaper ([0-9]+)<", string:resp);

if(!isnull(model[1]))md = model[1];

cpe = 'cpe:/h:bluecoat:packetshaper';

if(md) cpe += '_' + md;

set_kb_item(name:"bluecoat_packetshaper/installed", value:TRUE);
set_kb_item(name:string("bluecoat_packetshaper/port"), value:port);
set_kb_item(name:"www/"+port+"/packeteer", value:TRUE);

register_product(cpe:cpe, location:"/login.htm", port:port);

log_message(data: build_detection_report(app:"Packeteer/Bluecoat PacketShaper " + md, version:'unknown', install:'/', cpe:cpe, concluded: 'remote probe'),
            port:port);

exit(0);
