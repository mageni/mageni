###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_piwik_detect.nasl 12775 2018-12-12 13:35:45Z cfischer $
#
# Piwik Analytics Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.111046");
  script_version("$Revision: 12775 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-12 14:35:45 +0100 (Wed, 12 Dec 2018) $");
  script_tag(name:"creation_date", value:"2015-11-05 13:00:00 +0100 (Thu, 05 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Piwik Analytics Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://piwik.org/");

  script_tag(name:"summary", value:"The script sends a HTTP request to the server
  and attempts to identify Piwik and its version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
#include("cpe.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/piwik", "/analytics", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item:dir + "/index.php", port:port );

  if( buf =~ "^HTTP/1\.[01] 200" && ( eregmatch( pattern:'<title>.*Piwik.*</title>', string:buf, icase:TRUE ) ||
      ( "piwik.piwik_url" >< buf && ( "http://piwik.org" >< buf || "https://piwik.org" >< buf ) ) ) ) {

    version = "unknown";

    # nb: This isn't necessarily the "real" version, see https://github.com/matomo-org/matomo/issues/13827
    url = dir + "/CHANGELOG.md";
    buf = http_get_cache( item:url, port:port );

    ver = eregmatch( pattern:'## Piwik ([0-9.]+)', string:buf );
    if( ! isnull( ver[1] ) ) {
      #version  = ver[1];
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
      extra    = "Possible version gathered from the developers CHANGELOG.md: " + ver[1] + '\n';
      extra   += "NOTE: This version is not necessarily matching the running version and currently not used.";
    }

    #cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:piwik:piwik:");
    #if( isnull( cpe ) )
      cpe = "cpe:/a:piwik:piwik";

    set_kb_item( name:"www/" + port + "/piwik", value:version );
    set_kb_item( name:"piwik/installed", value:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Piwik",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              extra:extra,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );