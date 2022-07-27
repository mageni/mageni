# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105951");
  script_version("2022-03-23T15:48:29+0000");
  script_tag(name:"last_modification", value:"2022-03-23 15:48:29 +0000 (Wed, 23 Mar 2022)");
  script_tag(name:"creation_date", value:"2015-02-06 14:11:41 +0700 (Fri, 06 Feb 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Gogs (Go Git Service) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 3000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTT based detection of Gogs (Go Git Service).");

  script_xref(name:"URL", value:"https://gogs.io/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:3000 );

detection_patterns = make_list(
  # <title>Sign In - Gogs</title>
  # nb: Title tag can be changed by the admin so additional pattern are used.
  "^\s*<title>Sign In - Gogs[^<]*</title>",
  # Set-Cookie: i_like_gogs=cb882774ea538f46; Path=/; HttpOnly
  # Set-Cookie: i_like_gogits=3c1e042a611f849c; Path=/; HttpOnly
  # set-cookie: i_like_gogits=f21cdf87390436d8; Path=/; HttpOnly
  "^[Ss]et-[Cc]ookie\s*:\s*i_like_gog(it)?s=.+",
  # <meta name="author" content="Gogs" />
  # <meta name="description" content="Gogs is a painless self-hosted Git service" />
  # <meta name="keywords" content="go, git, self-hosted, gogs">
  '"description" content="Gogs is a painless self-hosted Git service"' );

foreach dir( make_list_unique( "/", "/gogs", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/user/login";
  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  found = 0;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach pattern( detection_patterns ) {

    concl = egrep( string:res, pattern:pattern, icase:FALSE );
    if( concl ) {
      if( concluded )
        concluded += '\n';

      # nb: Minor formatting change for the reporting.
      concl = chomp( concl );
      concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
      concluded += "  " + concl;

      found++;
    }
  }

  if( found > 0 ) {

    version = "unknown";
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    ver = eregmatch( string:res, pattern:"GoGits.*Version: ([0-9.]+)" );
    if ( ! isnull( ver[1] ) ) {
      version = ver[1];
      concluded += '\n  ' + ver[0];
    } else {
      # 2018 Gogs Version: 0.11.86.0130 Page: <strong>0ms</strong> Template: <strong>0ms</strong>
      # 2017 Gogs Version: 0.9.141.0211 Page: <strong>0ms</strong> Template: <strong>0ms</strong>
      ver = eregmatch( string:res, pattern:"Gogs Version: ([0-9.]+)" );
      if( ! isnull( ver[1] ) ) {
        version = ver[1];
        concluded += '\n  ' + ver[0];
      }
    }

    set_kb_item( name:"gogs/detected", value:TRUE );
    set_kb_item( name:"gogs/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base: "cpe:/a:gogs:gogs:" );
    if( ! cpe )
      cpe = "cpe:/a:gogs:gogs";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Gogs (Go Git Service)",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:concluded ),
                 port:port );

    goVersion = "unknown";

    # <span class="version">Go1.10.2</span>
    # <span class="version">Go1.7.5</span>
    goVer = eregmatch( string:res, pattern:'version">Go([0-9.]+)' );
    if( ! isnull( goVer[1] ) )
      goVersion = goVer[1];

    cpe = build_cpe( value:goVersion, exp:"^([0-9.]+)", base: "cpe:/a:golang:go:" );
    if( ! cpe )
      cpe = "cpe:/a:golang:go";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Go Programming Language",
                                              version:goVersion,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:goVer[0] ),
                 port:port );
  }
}

exit( 0 );
