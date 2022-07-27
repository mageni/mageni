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
  script_oid("1.3.6.1.4.1.25623.1.0.100061");
  script_version("2022-03-16T10:06:27+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-16 10:06:27 +0000 (Wed, 16 Mar 2022)");
  script_tag(name:"creation_date", value:"2009-03-19 11:22:36 +0100 (Thu, 19 Mar 2009)");
  script_name("MantisBT Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.mantisbt.org/");

  script_tag(name:"summary", value:"HTTP based detection of MantisBT.");

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

foreach dir( make_list_unique( "/mantis", "/mantisbt", "/bugs", "/bugtracker", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/login_page.php";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
    continue;

  if( egrep( pattern:"Copyright &copy;.*Mantis Group", string:buf ) ||
      egrep( pattern:"Powered by Mantis Bugtracker", string:buf ) ||
      egrep( pattern:"Powered by.*>MantisBT", string:buf ) ||
      egrep( pattern:"Mantis Bugtracker", string:buf ) ||
      egrep( pattern:"Copyright &copy;.*MantisBT Team", string:buf ) ||
      egrep( pattern:"Copyright &copy;.*MantisBT Group", string:buf ) ||
      '" title="MantisBT: ' >< buf || '/css/ace-mantis.css" />' >< buf ||
      '/images/mantis_logo.png">' >< buf ) {

    version = "unknown";
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( string:buf, pattern:"Mantis ([0-9]+\.+[0-9]*\.*[0-9]*[a-zA-Z0-9]*)" );
    if( ! vers[1] )
      vers = eregmatch( string:buf, pattern:">MantisBT ([0-9.]+)" );

    if( ! vers[1] )
      vers = eregmatch( string:buf, pattern:">MantisBT  ([0-9.]+(-[a-z0-9.]+)?)" );

    if( vers[1] ) {
      version = vers[1];
      concluded = vers[0];
    }

    if( version == "unknown" ) {

      # nb: /doc dir is sometimes unprotected
      url = dir + "/doc/RELEASE";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
      vers = eregmatch( string:buf, pattern:"([0-9.]+(-[a-z0-9.]+)?) (Maintenance|Stable|Security) Release" );
      if( buf =~ "^HTTP/1\.[01] 200" && vers[1] ) {
        version = vers[1];
        conclUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        concluded = vers[0];
      }
    }

    if( version == "unknown" ) {

      # Mantis 1.3.0+
      url = dir + "/doc/en-US/Developers_Guide/Developers_Guide.txt";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
      vers = eregmatch( string:buf, pattern:"Release ([0-9.]+(-[a-z0-9.]+)?)" );
      if( buf =~ "^HTTP/1\.[01] 200" && vers[1] ) {
        version = vers[1];
        conclUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        concluded = vers[0];
      }
    }

    set_kb_item( name:"mantisbt/detected", value:TRUE );
    set_kb_item( name:"mantisbt/http/detected", value:TRUE );

    # nb: not possible to combine cpe regex due to way cpe.inc is handling regular expression
    if( version =~ "^([0-9.]+-[a-zA-Z0-9.]+)" ) {
      cpe = build_cpe( value:version, exp:"([0-9.]+-[a-zA-Z0-9.]+)", base:"cpe:/a:mantisbt:mantisbt:" );
    } else if( version =~ "^([0-9.]+[a-zA-Z0-9.]+)" ) {
      cpe = build_cpe( value:version, exp:"([0-9.]+[a-zA-Z0-9.]+)", base:"cpe:/a:mantisbt:mantisbt:" );
    } else {
      cpe = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:mantisbt:mantisbt:" );
    }

    if( ! cpe )
      cpe = "cpe:/a:mantisbt:mantisbt";

    register_product( cpe:cpe, location:install, port:port, service:"www" );
    log_message( data:build_detection_report( app:"MantisBT",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:concluded ),
                 port:port );
  }
}

exit( 0 );
