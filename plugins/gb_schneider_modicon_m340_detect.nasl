###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_schneider_modicon_m340_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Schneider Electric Modicon M340 Detection (http)
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
  script_oid("1.3.6.1.4.1.25623.1.0.103856");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-12-16 11:11:45 +0100 (Mon, 16 Dec 2013)");
  script_name("Schneider Electric Modicon M340 Detection (http)");

  script_tag(name:"summary", value:"Detection of Schneider Electric Modicon M340 over HTTP.

The script sends a HTTP request to the server and attempts to detect a Schneider Modicon M340 from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Schneider-WEB/banner");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");

include("host_details.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("Server: Schneider-WEB" >!< banner)exit(0);

url = '/html/english/index.htm';
req = http_get(item:url, port:port);

buf = http_send_recv(port:port, data:req, bodyonly:TRUE);
if(buf !~ '<title>.* (BMX P34) .*</title>')exit(0);

set_kb_item(name:"schneider_modicon_m340/installed", value:TRUE);

cpe = 'cpe:/h:schneider-electric:modicon_m340';
register_product(cpe:cpe, location:'/', port:port, service: 'www');
log_message(data: 'The remote Host is a Schneider Modicon M340.\nCPE: ' + cpe + '\nLocation: /\n', port:port);

exit(0);

