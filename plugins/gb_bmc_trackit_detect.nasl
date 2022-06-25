###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bmc_trackit_detect.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# BMC Track-It! Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105931");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10898 $");
  script_name("BMC Track-It! Detection");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-11-26 11:10:03 +0700 (Wed, 26 Nov 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"The script sends a connection request
  to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);

foreach dir( make_list_unique( "/TrackItWeb", "/tiweb", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/Account/LogIn";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf == NULL ) continue;

  check = dir + "/Content";
  if( buf =~ 'HTTP/1.. 200' && check >< buf ) {

    vers = "unknown";
    concludedUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

    version =  eregmatch( string:buf, pattern:check + "\.([0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,4})" );
    if( ! isnull( version[1] ) ) {
      vers = chomp( version[1] );
    }

    tmp_version = vers + " under " + install;
    set_kb_item( name:"www/" + port + "/bmctrackit", value:tmp_version );
    set_kb_item( name:"bmctrackit/installed", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,4})", base:"cpe:/a:bmc:bmc_track-it!:" );
    if( ! cpe )
      cpe = 'cpe:/a:bmc:bmc_track-it!';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"BMC Track-It!",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0],
                                              concludedUrl:concludedUrl ),
                                              port:port );
  }
}

exit( 0 );
