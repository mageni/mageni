# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100204");
  script_version("2023-02-03T10:10:17+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-02-03 10:10:17 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"creation_date", value:"2009-05-16 14:32:16 +0200 (Sat, 16 May 2009)");
  script_name("Cacti Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.cacti.net/");

  script_tag(name:"summary", value:"HTTP based detection of Cacti.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

detection_patterns = make_list(
  # <div class='versionInfo'>Version new_install | (c) 2004-2017 - The Cacti Group</div>
  # <div class="copyRightInfo">Copyright &copy; 2001-2011 <br/>The Cacti Group&trade;. <br/>All rights reserved.</div>
  # <div class='versionInfo'>Version 1.2.1 | (c) 2004-2023 - The Cacti Group - somestring</div>
  # <div class='versionInfo'>(c) 2004-2023 - The Cacti Group</div>
  ">[^>]*The Cacti Group[^<]*",
  # <title>Login to Cacti</title>
  "^\s*<title>[^>]*Login to Cacti[^<]*</title>",
  # <link href='/include/themes/classic/images/cacti_logo.gif'
  # <link href='/include/themes/modern/images/cacti_logo.gif'
  # <link href='/cacti/include/themes/paw/images/cacti_logo.gif'
  "/include/themes/.+/images/cacti_logo\.gif",
  # nb: This seems to be from a different (older?) theme
  # <img src="/cacti/images/auth_login.gif"
  # <img src="images/auth_login.gif" border="0" alt=""></td>
  '<img src="/?(cacti/)?images/auth_login\\.gif"',
  # Set-Cookie: Cacti=<redacted>; path=/
  # Set-Cookie: CactiEZ=<redacted>; path=/
  "^[Ss]et-[Cc]ookie\s*:\s*Cacti[^=]*=[^;]+;" );

# nb: Don't add an initial "/" to this list as some system seems to respond on "/" and "/cacti"
# (probably due to some rewrites) and the "/cacti" one seems to better fit...
foreach dir( make_list_unique( "/cacti", "/monitoring", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
    continue;

  found = 0;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach pattern( detection_patterns ) {

    concl = egrep( string:buf, pattern:pattern, icase:FALSE );
    if( concl ) {

      found++;

      if( concluded )
        concluded += '\n';
      # nb: Minor formatting change for the reporting.
      concl = chomp( concl );
      concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
      concluded += "  " + concl;
    }
  }

  if( found > 1 ) {

    concUrl = "  " + http_report_vuln_url( url:url, port:port, url_only:TRUE );
    version = "unknown";

    # <div class='versionInfo'>Version 1.2.1 | (c) 2004-2023
    vers = eregmatch( pattern:"versionInfo'>Version ([0-9.]+[a-z]{0,1})", string:buf );
    if( vers[1] ) {
      version = vers[1];
      concluded += '\n  ' + vers[0];
    }

    if( version == "unknown" ) {
      # <div class="productName">Cacti 0.8.8a</div>
      vers = eregmatch( pattern:'productName">Cacti ([0-9.]+[a-z]{0,1})', string:buf );
      if( vers[1] ) {
        version = vers[1];
        concluded += '\n  ' + vers[0];
      }
    }

    if( version == "unknown" ) {

      # nb:
      # - On newer versions the CHANGELOG seems to be located in the main dir
      # - If we're in the "/cacti" subdir we're also trying "/CHANGELOG" just to be sure
      urls = make_list( dir + "/docs/CHANGELOG", dir + "/CHANGELOG" );
      if( dir != "/" )
        urls = make_list( urls, "/docs/CHANGELOG", "/CHANGELOG" );

      foreach url( urls ) {

        buf = http_get_cache( item:url, port:port );

        if( buf && buf =~ "^HTTP/1\.[01] 200" && "Cacti CHANGELOG" >< buf ) {
          vers = eregmatch( string:buf, pattern:"Cacti CHANGELOG\s+([0-9.]+[a-z]{0,1})", icase:FALSE );
          if( vers[1] ) {
            version = vers[1];
            concluded += '\n  ' + ereg_replace( string:vers[0], pattern:'[\r\n]+', replace:"<newline>" );
            concUrl += '\n  ' + http_report_vuln_url( url:url, port:port, url_only:TRUE );
            break;
          }
        }
      }
    }

    set_kb_item( name:"cacti/detected", value:TRUE );
    set_kb_item( name:"cacti/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"([0-9.]+[a-z]{0,1})", base:"cpe:/a:cacti:cacti:" );
    if( ! cpe )
      cpe = "cpe:/a:cacti:cacti";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Cacti",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:concluded,
                                              concludedUrl:concUrl ),
                 port:port );
    exit( 0 ); # nb: Usually only installed once. Also avoid that an installation is detected on "/" and "/cacti
  }
}

exit( 0 );
