###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_FishEye_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# FishEye Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100864");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2010-10-21 13:52:26 +0200 (Thu, 21 Oct 2010)");
  script_name("FishEye Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"Detection of FishEye.

The script sends a connection request to the server and attempts to
extract the version number from the reply.");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

foreach dir( make_list_unique( "/", "/fisheye", cgi_dirs( port:port ) ) ) {

  install = dir;
  if(dir == "/") dir = "";
  url = string(dir,"/admin/login-default.do");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( buf == NULL )continue;

  if("<h3>Administration log in to FishEye" >< buf) {

     vers = string("unknown");
     version = eregmatch(string: buf, pattern: "(\(Version:([0-9.]+))");

     if ( !isnull(version[2]) ) {
        vers=chomp(version[2]);
     }

     set_kb_item(name: string("www/", port, "/FishEye"), value: string(vers));
     set_kb_item(name:"FishEye/installed", value:TRUE);

     cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:atlassian:fisheye:");

     if(isnull(cpe))
       cpe = 'cpe:/a:atlassian:fisheye';

     register_product(cpe:cpe, location:install, port:port);

     log_message(data: build_detection_report(app:"FishEye", version:vers, install:install, cpe:cpe, concluded: version[1]),
                 port:port);

     exit(0);

  }

}

exit(0);
