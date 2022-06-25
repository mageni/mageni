###############################################################################
# OpenVAS Vulnerability Test
# $Id: invision_power_board_detect.nasl 11894 2018-10-13 07:46:55Z cfischer $
#
# IP.Board Detection
#
# Authors:
# Michael Meyer
#
# Updated to include upload directory and set multiple versions.
#  - By Nikita MR <rnikita@secpod.com> on 2009-11-20 15:25:02Z
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# Updated to detect IPB versions 2.3.3 and 2.3.5
#   -By Sharath S <sharaths@secpod.com> on 2009-04-09
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100107");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11894 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-13 09:46:55 +0200 (Sat, 13 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-04-06 18:10:45 +0200 (Mon, 06 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IP.Board Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of IP.Board.

  The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

foreach mdir( make_list_unique( "/forum", "/board", "/ipb", "/community", "/", cgi_dirs( port:port ) ) ) {

  install = mdir;
  if( mdir == "/" ) mdir = "";

  foreach dir( make_list( "/", "/upload/" ) ) {
    url = mdir + dir + "index.php";
    buf = http_get_cache(item:url, port:port);

    if(egrep(pattern:"Powered [Bb]y ?(<a [^>]+>)?(Invision Power Board|IP.Board)",
             string: buf, icase: TRUE) || egrep(pattern:"Invision Power Board</title>",
             string: buf, icase: TRUE ) || egrep(pattern:"Community Forum Software by IP.Board",
             string: buf, icase: TRUE ))
    {
      vers = "unknown";

      version = eregmatch(pattern:"v*([0-9.]+[a-zA-Z ]*) &copy;.*[0-9]{4}.*IPS.*", string:buf, icase:TRUE);
      if (!isnull(version[1]))
        vers = version[1];
      else {
        version = eregmatch(pattern: "Community Forum Software by IP.Board ([0-9.]+)", string: buf, icase:TRUE);
        if (!isnull(version[1]))
          vers = version[1];
      }

      set_kb_item(name:"invision_power_board/installed", value:TRUE);

      register_and_report_cpe(app: "IP.Board", ver: vers,
                              base: "cpe:/a:invision_power_services:invision_power_board:",
                              expr: "^([0-9.]+([a-z0-9]+)?)", insloc: install, concluded: version[0],
                              regPort: port );
      exit(0);
    }
  }
}

exit( 0 );