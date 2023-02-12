# Copyright (C) 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111027");
  script_version("2023-02-06T10:09:59+0000");
  script_tag(name:"last_modification", value:"2023-02-06 10:09:59 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"creation_date", value:"2015-08-21 16:00:00 +0200 (Fri, 21 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Roundcube Webmail Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://roundcube.net");

  script_tag(name:"summary", value:"HTTP based detection of Roundcube Webmail.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/roundcube", "/webmail", "/mail", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";
  buf = http_get_cache( item:url, port:port );
  if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
    continue;

  # <meta http-equiv="content-type" content="text/html; charset=UTF-8"><title>Roundcube Webmail :: Welcome to Roundcube Webmail</title>
  # <title>Roundcube Webmail :: </title>
  # <title>RoundCube Webmail :: Welcome to RoundCube Webmail</title>
  # <meta http-equiv="content-type" content="text/html; charset=UTF-8"><title>$somestring: Roundcube Webmail :: Welcome to $somestring: Roundcube Webmail</title>
  # <title>Roundcube Webmail :: ERROR</title>
  if( eregmatch( pattern:"<title>[^<]*Round[Cc]ube Webmail[^<]*</title>", string:buf, icase:FALSE ) ||
      ( "rcmloginuser" >< buf && "rcmloginpwd" >< buf ) || "new rcube_webmail();" >< buf ) {

    version = "unknown";
    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    # nb:
    # - Since version 1.5.0 the project has switched from a CHANGELOG to CHANGELOG.md as seen here:
    #   - https://github.com/roundcube/roundcubemail/blob/1.4.13/CHANGELOG
    #   - https://raw.githubusercontent.com/roundcube/roundcubemail/1.5.0/CHANGELOG.md
    # - As an update might have left the older CHANGELOG behind (happens when using their upgrade
    #   script) we're trying the .md first and falling back to the older afterwards
    # - The "RELEASE 1.2.3" string below seems to be available since around version 0.4.1:
    #   https://github.com/roundcube/roundcubemail/blob/v0.4.2/CHANGELOG
    #   which should be enough for our purpose
    # - Both currently below tested "initial" response checks have been checked starting from
    #   version 0.4.1 up to the current 1.6.1

    foreach url( make_list( dir + "/CHANGELOG.md", dir + "/CHANGELOG" ) ) {

      buf = http_get_cache( item:url, port:port );
      if( ! buf || buf !~ "^HTTP/1\.[01] 200" ||
          ( "# Changelog Roundcube Webmail" >!< buf && "CHANGELOG Roundcube Webmail" >!< buf )
        )
        continue;

      # ## Release 1.6.1
      # RELEASE 1.4.13
      # RELEASE 0.4.1
      # RELEASE 0.5-RC
      vers = eregmatch( pattern:"(RELEASE|## Release) (([0-9.]+)(-([a-zA-Z]+))?)", string:buf, icase:FALSE );
      if( ! isnull( vers[2] ) ) {
        version = vers[2];
        conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        break;
      }
    }

    cpe = "cpe:/a:roundcube:webmail";
    if( version != "unknown" ) {
      # nb: Example array indices:
      # [ 0: 'RELEASE 0.5-RC', 1: 'RELEASE', 2: '0.5-RC', 3: '0.5', 4: '-RC', 5: 'RC' ]
      # [ 0: '## Release 1.5.3', 1: '## Release', 2: '1.5.3', 3: '1.5.3' ]
      if( ! isnull( vers[4] ) )
        cpe = cpe + ":" + vers[3] + ":" + tolower( vers[5] );
      else
        cpe = cpe + ":" + version;
    }

    set_kb_item( name:"roundcube/detected", value:TRUE );
    set_kb_item( name:"roundcube/http/detected", value:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Roundcube Webmail",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:vers[0] ),
                 port:port );
  }
}

exit( 0 );
