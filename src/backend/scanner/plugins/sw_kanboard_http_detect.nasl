# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111062");
  script_version("2023-07-12T05:05:05+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:05 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-03 15:00:00 +0100 (Thu, 03 Dec 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Kanboard Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Kanboard.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/kanboard", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled )
    break;

  install = dir;
  if( dir == "/" )
    dir = "";

  found = FALSE;
  url = dir + "/?controller=auth&action=login";

  buf = http_get_cache( port:port, item:url );

  if( "<title>Login</title>" >< buf && "data-status-url" >< buf ) {
    found = TRUE;
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  if ( ! found ) {
    url = dir + "/?controller=AuthController&action=login";
    buf = http_get_cache( port:port, item:url );
    if( buf =~ "<title>\s*Login\s*</title>" && "data-status-url" >< buf ) {
      found = TRUE;
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }

  if ( ! found ) {
    url = dir + "/jsonrpc.php";
    buf = http_get_cache( port:port, item:url );
    if( '{"jsonrpc":"' >< buf && 'Parse error"}' >< buf ) {
      found = TRUE;
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }

  if ( ! found ) {
    url = dir + "/?controller=user&action=login";
    buf = http_get_cache( port:port, item:url );
    if( "<title>Login - Kanboard</title>" >< buf || "Internal Error: Action not implemented" >< buf ) {
      found = TRUE;
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }
  if( found ) {
    version = "unknown";

    if( dir == "" )
      rootInstalled = 1;

    url = dir + "/ChangeLog";
    buf = http_get_cache( port:port, item:url );

    ver = eregmatch( pattern:"Version ([0-9.]+)", string:buf );

    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      concluded = ver[0];
      conclUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:kanboard:kanboard:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:kanboard:kanboard';

    set_kb_item( name:"kanboard/detected", value:TRUE );
    set_kb_item( name:"kanboard/http/detected", value:TRUE );
    set_kb_item( name:"kanboard/" + port + "/version", value:version );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Kanboard",
                                              version:version,
                                              concluded:concluded,
                                              concludedUrl:conclUrl,
                                              install:install,
                                              cpe:cpe ),
                                              port:port );
  }
}

exit( 0 );
