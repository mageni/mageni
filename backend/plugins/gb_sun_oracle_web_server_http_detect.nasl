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
  script_oid("1.3.6.1.4.1.25623.1.0.800810");
  script_version("2021-05-03T14:25:58+0000");
  script_tag(name:"last_modification", value:"2021-05-04 10:22:24 +0000 (Tue, 04 May 2021)");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sun/Oracle Web Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("sun_oracle/web_servers/banner");

  script_tag(name:"summary", value:"HTTP based detection of various Sun/Oracle Web Server products.");

  script_tag(name:"insight", value:"The following products are currently detected:

  - Oracle iPlanet Web Server

  - Sun ONE Web Server

  - Sun Java System Web Server");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );
if( ! banner || banner !~ "(Server|Www-authenticate|Proxy-agent)\s*:.+" )
  exit( 0 );

# Server: Oracle-iPlanet-Web-Server/7.0
# Www-authenticate: Basic realm="Oracle iPlanet Web Server"
# Proxy-agent: Oracle-iPlanet-Web-Server/7.0
if( concl = egrep( string:banner, pattern:'^((Server|Proxy-agent)\\s*:\\s*Oracle-iPlanet-Web-Server|Www-authenticate\\s*:\\s*Basic realm="Oracle iPlanet Web Server")', icase:TRUE ) ) {
  oracle_iplanet_concluded = chomp( concl );
  is_oracle_iplanet = TRUE;
  found = TRUE;
}

# Server: Sun-Java-System-Web-Server/7.0
if( concl = egrep( string:banner, pattern:"^Server\s*:\s*Sun-Java-System-Web-Server", icase:TRUE ) ) {
  sun_java_system_concluded = chomp( concl );
  is_sun_java_system = TRUE;
  found = TRUE;
}

# Server: Sun-ONE-Web-Server/6.1
if( concl = egrep( string:banner, pattern:"^Server\s*:\s*Sun-ONE-Web-Server", icase:TRUE ) ) {
  sun_one_concluded = chomp( concl );
  is_sun_one = TRUE;
  found = TRUE;
}

if( found ) {

  install = port + "/tcp";

  url = "/admingui/version/copyright";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port: port, data:req );

  if( "Sun Java System Web Server" >< res || is_sun_java_system ) {

    version = "unknown";

    app = "Sun Java System Web Server";
    vers = eregmatch( pattern:"Sun[ |-]Java[ |-]System[ |-]Web[ |-]Server[ |/]([0-9.]+)", string:sun_java_system_concluded );
    if( vers[1] )
      version = vers[1];

    if( version == "unknown" ) {
      vers = eregmatch( pattern:"Sun[ |-]Java[ |-]System[ |-]Web[ |-]Server[ |/]([0-9.]+)", string:res );
      if( vers[1] ) {
        version = vers[1];
        concl_url = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    set_kb_item( name:"sun/java_system_web_server/detected", value:TRUE );
    set_kb_item( name:"sun/java_system_web_server/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:sun:java_system_web_server:" );
    if( ! cpe )
      cpe = "cpe:/a:sun:java_system_web_server";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:app,
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:sun_java_system_concluded,
                                              concludedUrl:concl_url ),
                 port:port );
  }

  if( "Oracle iPlanet Web Server" >< res || is_oracle_iplanet ) {

    version = "unknown";

    vers = eregmatch( pattern:"Oracle[ |-]iPlanet[ |-]Web[ |-]Server[ |/]([0-9.]+)", string:oracle_iplanet_concluded );
    if( vers[1] )
      version = vers[1];

    if( version == "unknown" ) {
      vers = eregmatch( pattern:"Oracle[ |-]iPlanet[ |-]Web[ |-]Server[ |/]([0-9.]+)", string:res );
      if( vers[1] ) {
        version = vers[1];
        concl_url = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    set_kb_item( name:"oracle/iplanet_web_server/detected", value:TRUE );
    set_kb_item( name:"oracle/iplanet_web_server/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:oracle:iplanet_web_server:" );
    if( ! cpe )
      cpe = "cpe:/a:oracle:iplanet_web_server";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Oracle iPlanet Web Server",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:oracle_iplanet_concluded,
                                              concludedUrl:concl_url ),
                 port:port );
  }

  if( is_sun_one ) {

    version = "unknown";

    vers = eregmatch( pattern:"Sun-ONE-Web-Server/([0-9.]+)", string:sun_one_concluded );
    if( vers[1] )
      version = vers[1];

    set_kb_item( name:"sun/one_web_server/detected", value:TRUE );
    set_kb_item( name:"sun/one_web_server/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:sun:one_web_server:" );
    if( ! cpe )
      cpe = "cpe:/a:sun:one_web_server";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Sun ONE Web Server",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:sun_one_concluded ),
                 port:port );
  }
}

exit( 0 );