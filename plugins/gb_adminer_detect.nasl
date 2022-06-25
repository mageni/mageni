###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adminer_detect.nasl 13205 2019-01-21 17:38:02Z cfischer $
#
# Adminer Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108531");
  script_version("$Revision: 13205 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 18:38:02 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-20 14:05:39 +0100 (Sun, 20 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Adminer Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 12322); # Second port is from TurnKeyLAMP
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.adminer.org/");

  script_tag(name:"summary", value:"The script sends a HTTP request to the remote
  server and tries to identify an Adminer installation and it's version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) )
  exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/adminer", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  if( rootInstalled )
    break;

  url  = dir + "/adminer.php";
  buf  = http_get_cache( item:url, port:port );

  url2 = dir + "/";
  buf2 = http_get_cache( item:url2, port:port );

  if( ( buf =~ "^HTTP/1\.[01] 200" || buf2 =~ "^HTTP/1\.[01] 200" ) &&
      ( "<title>Login - Adminer</title>" >< buf ||
        "<title>Login - Adminer</title>" >< buf2 ||
        ( "://www.adminer.org/'" >< buf && "id='h1'>Adminer</a>" >< buf ) ||
        ( "://www.adminer.org/'" >< buf2 && "id='h1'>Adminer</a>" >< buf2 ) ) ) {

    version = "unknown";
    conclUrl = report_vuln_url( port:port, url:url2, url_only:TRUE );
    if( install == "/" )
      rootInstalled = TRUE;

    # onload: partial(verifyVersion, '4.7.0', '?', '674453:67503')});
    # id='h1'>Adminer</a> <span class="version">4.7.0</span>
    #
    # onclick="bodyClick(event);" onload="verifyVersion('4.2.5');">
    # id='h1'>Adminer</a> <span class="version">4.2.5</span>

    vers = eregmatch( pattern:"verifyVersion(, '|\(')([^']+)'", string:buf, icase:FALSE );
    if( vers[2] ) {
      version = vers[2];
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    if( version == "unknown" ) {
      vers = eregmatch( pattern:"verifyVersion(, '|\(')([^']+)'", string:buf2, icase:FALSE );
      if( vers[2] ) {
        version = vers[2];
        conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    if( version == "unknown" ) {
      vers = eregmatch( pattern:'class="version">([^<]+)<', string:buf, icase:FALSE );
      if( vers[1] ) {
        version = vers[1];
        conclUrl = report_vuln_url( port:port, url:url2, url_only:TRUE );
      }
    }

    if( version == "unknown" ) {
      vers = eregmatch( pattern:'class="version">([^<]+)<', string:buf2, icase:FALSE );
      if( vers[1] ) {
        version = vers[1];
        conclUrl = report_vuln_url( port:port, url:url2, url_only:TRUE );
      }
    }

    set_kb_item( name:"www/" + port + "/adminer", value:version );
    set_kb_item( name:"adminer/detected", value:TRUE );
    register_and_report_cpe( app:"Adminer", ver:version, concluded:vers[0], conclUrl:conclUrl, base:"cpe:/a:adminer:adminer:", expr:"^([0-9.]+)", insloc:install, regPort:port, regService:"www" );
  }
}

exit( 0 );