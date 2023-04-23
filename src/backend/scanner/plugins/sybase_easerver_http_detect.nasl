# SPDX-FileCopyrightText: 2008 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80006");
  script_version("2023-04-04T10:10:18+0000");
  script_tag(name:"last_modification", value:"2023-04-04 10:10:18 +0000 (Tue, 04 Apr 2023)");
  script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sybase Enterprise Application Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Christian Eric Edjenguele");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Sybase Enterprise Application Server.");

  script_xref(name:"URL", value:"https://www.sybase.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

buf = http_get_cache( port:port, item:"/" );

version = "unknown";
location = "/";
concluded = ""; # nb: To make openvas-nasl-lint happy...

if( "<TITLE>Sybase EAServer<" >< buf || egrep( pattern:"Sybase EAServer", string:buf ) ||
    "<title>Sybase Enterprise Application Server" >< buf ) {

  identified = 1;
  ver = eregmatch( pattern:'EAServer ([0-9.]+)', string:buf );
  if( isnull( ver[1] ) ) {
    # Server: Jetty(EAServer/6.3.1.07 Build 63107)
    ver = eregmatch( pattern:"EAServer/([0-9.]+)", string:buf );
    if( isnull( ver[1] ) ) {
      # <CENTER> Sybase Enterprise Application Server 6.3.1 [nt386] Build (63104)<p>
      ver = eregmatch( pattern:"<CENTER>\s*Sybase Enterprise Application Server ([0-9.]+)", string:buf );
    }
  }

  if( ! isnull( ver[1] ) ) {
    version = ver[1];
    concluded += '\n- ' + ver[0];
  }
}

url = "/WebConsole/Login.jsp";
buf = http_get_cache( port:port, item:url );

if( detectedConsole = eregmatch( string: buf, pattern: "Sybase Management Console Login" ) ) {
  identified = 1;
  concluded += '\n- ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  set_kb_item( name:"sybase/jsp_console/detected", value:TRUE );
} else {
  url = "/console/Login.jsp";
  buf = http_get_cache( port:port, item:url );
  if( detectedConsole = eregmatch( string: buf, pattern: "Sybase Management Console Login" ) ) {
    identified = 1;
    concluded += '\n- ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    set_kb_item( name:"sybase/jsp_console/detected", value:TRUE );
  }
}

banner = http_get_remote_headers( port:port );

if( detectedBanner = eregmatch( string: banner, pattern: "Server: Jaguar Server Version([ 0-9.]+)", icase: TRUE ) ) {
  identified = 1;
  concluded += '\n- ' + detectedBanner[0];
}

if( identified ) {
  set_kb_item( name:"sybase/easerver/detected", value:TRUE );
  set_kb_item( name:"sybase/easerver/http/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:sybase:easerver:");
  if( ! cpe )
    cpe = "cpe:/a:sybase:easerver";

  register_product( cpe:cpe, location:location, port:port, service:"www" );

  log_message( data: build_detection_report( app:"Sybase Enterprise Application Server",
                                             version:version, install:location, cpe:cpe, concluded:concluded ),
               port:port );
  exit( 0 );
}

exit( 0 );
