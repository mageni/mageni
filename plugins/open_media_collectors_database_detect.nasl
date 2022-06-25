###############################################################################
# OpenVAS Vulnerability Test
# $Id: open_media_collectors_database_detect.nasl 14121 2019-03-13 06:21:23Z ckuersteiner $
#
# Open Media Collectors Database Detection
#
# Authors:
# Michael Meyer
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100468");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 14121 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 07:21:23 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-26 20:04:43 +0100 (Tue, 26 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Open Media Collectors Database Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running Open Media Collectors Database, a PHP and MySQL
  based inventory application.");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/opendb/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

SCRIPT_DESC = "Open Media Collectors Database Detection";

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/opendb", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/login.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if(egrep(pattern: "<title>Open Media Collectors Database - Login</title>", string: buf, icase: TRUE) &&
    "Powered by OpenDb" >< buf)
 {
    vers = "unknown";
    version = eregmatch(string: buf, pattern: "Powered by OpenDb ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) )
       vers = version[1];

    set_kb_item(name: "opendb/detected", value: TRUE);

    cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:opendb:opendb:");
    if (!cpe)
      cpe = 'cpe:/a:opendb:opendb';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Open Media Collectors Database", version: vers,
                                             install: install, cpe: cpe, concluded: version[0]),
                port: port);
    exit(0);
  }
}

exit(0);
