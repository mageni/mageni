###############################################################################
# OpenVAS Vulnerability Test
# $Id: flatpress_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Flatpress Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100294");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-10-06 18:45:43 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Flatpress Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running Flatpress, an open-source blogging engine.");

  script_xref(name:"URL", value:"http://www.flatpress.org");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port))exit(0);

foreach dir ( make_list_unique( "/flatpress", "/blog", cgi_dirs( port: port))) {
 install = dir;
 if (dir == "/") dir = "";

 url = dir + "/index.php";
 buf = http_get_cache( item: url, port: port );
 if( buf == NULL ) continue;

 if (egrep(pattern: "powered by <a [^>]>FlatPress", string: buf, icase: TRUE) ||
     egrep(pattern: 'meta name="generator" content="FlatPress', string: buf, icase: TRUE)) {
   vers = "unknown";

   version = eregmatch(string: buf, pattern: 'FlatPress fp-([0-9.]+[^"]*)',icase: TRUE);
   if (!isnull(version[1]))
       vers = version[1];

   set_kb_item(name: "flatpress/installed", value: TRUE);

   cpe = build_cpe(value: vers, exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:flatpress:flatpress:");
   if (!cpe)
     cpe = 'cpe:/a:flatpress:flatpress';

   register_product(cpe: cpe, location: install, port: port);

   log_message(data: build_detection_report(app: "FlatPress", version: vers, install: install, cpe: cpe,
                                            concluded: version[0]),
               port: port);
   exit(0);
 }
}

exit(0);
