###############################################################################
# OpenVAS Vulnerability Test
# $Id: FreeWebShop_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# FreeWebShop Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100235");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-07-21 20:55:39 +0200 (Tue, 21 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("FreeWebShop Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of FreeWebShop.

The script sends a connection request to the server and attempts to extract the version number from the reply.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/freewebshop", "/shop", cgi_dirs( port:port ) ) ) {
 install = dir;
 if( dir == "/" ) dir = "";

 url = dir + "/index.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if (egrep(pattern: "powered by FreeWebshop.org", string: buf, icase: TRUE)) {
   vers = "unknown";

   url = dir + "/docs/changelog.txt";
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

   version = eregmatch(string: buf, pattern: "Version[^:]+:.([0-9.]+[_R[0-9]*)",icase:TRUE);
   if (!isnull(version[1])) {
     vers = version[1];
     concUrl = url;
   }

   set_kb_item(name:"FreeWebshop/installed", value:TRUE);

   cpe = build_cpe(value: vers, exp: "^([0-9.]+\.[0-9]\.?[_r0-9]+?)", base: "cpe:/a:freewebshop:freewebshop:");
   if(!cpe)
     cpe = 'cpe:/a:freewebshop:freewebshop';

   register_product(cpe:cpe, location:install, port:port);

   log_message(data: build_detection_report(app:"FreeWebshop", version:vers, install:install, cpe:cpe,
                                            concluded: version[0], concludedUrl: concUrl),
               port:port);
   exit(0);
 }
}

exit(0);
