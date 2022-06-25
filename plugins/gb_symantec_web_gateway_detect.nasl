###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# Symantec Web Gateway Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103483");
  script_version("$Revision: 10911 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-05-04 17:35:57 +0200 (Fri, 04 May 2012)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Symantec Web Gateway Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Symantec Web Gateway.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

symPort = get_http_port(default:80);
if(!can_host_php(port:symPort))exit(0);

foreach dir( make_list_unique( "/", cgi_dirs( port:symPort ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = string(dir, "/spywall/login.php");
  req = http_get(item:url, port:symPort);
  buf = http_keepalive_send_recv(port:symPort, data:req, bodyonly:FALSE);
  if(buf == NULL) continue;

  if(egrep(pattern: "<title>Symantec Web Gateway - Login", string: buf, icase: TRUE))
  {
    vers = string("unknown");

    version = eregmatch(string: buf, pattern: ">(Version ([0-9.]+))<",icase:TRUE);

    if ( !isnull(version[2]) ) {
      vers=chomp(version[2]);
    }

    set_kb_item(name: string("www/", symPort, "/symantec_web_gateway"), value: string(vers," under ",install));
    set_kb_item(name:"symantec_web_gateway/installed",value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:symantec:web_gateway:");
    if(isnull(cpe))
      cpe = 'cpe:/a:symantec:web_gateway';

    register_product(cpe:cpe, location:install, port:symPort);

    log_message(data: build_detection_report(app:"Symantec Web Gateway",
                                             version:vers,
                                             install:install,
                                             cpe:cpe,
                                             concluded: version[1]),
                                             port:symPort);

  }
}

exit( 0 );