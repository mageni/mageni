###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_icingaweb2_detect.nasl 11021 2018-08-17 07:48:11Z cfischer $
#
# Icinga Web 2 Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111055");
  script_version("$Revision: 11021 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:48:11 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-11-21 19:00:00 +0100 (Sat, 21 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Icinga Web 2 Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request
  to the server and attempts to extract the version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/icinga", "/icingaweb2", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/authentication/login";
  req = http_get_req( port:port, url:url, add_headers:make_array( "Cookie", "_chc=1" ) );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf =~ "^HTTP/1\.[01] 200" &&
      ( "<title>Icinga Web 2 Login" >< buf ||
        "Icinga Web 2 &copy; 20" >< buf ||
        "var icinga = new Icinga" >< buf ) ) {

    version = "unknown";
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

    #CPE not registered/available yet
    cpe = 'cpe:/a:icinga:icingaweb2';

    set_kb_item( name:"www/" + port + "/icingaweb2", value:version );
    set_kb_item( name:"icingaweb2/installed", value:TRUE );

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Icinga Web 2",
                                              version:version,
                                              install:install,
                                              concludedUrl:conclUrl,
                                              cpe:cpe ),
                                              port:port );
  }
}

exit( 0 );
