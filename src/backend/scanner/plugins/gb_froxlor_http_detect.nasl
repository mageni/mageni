# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106035");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2015-08-03 13:44:55 +0700 (Mon, 03 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Froxlor Server Management Panel Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Froxlor Server Management Panel.");

  script_xref(name:"URL", value:"https://froxlor.org/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/froxlor", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( port:port, item:url );

  if( "Froxlor Server Management Panel" >< res && ">the Froxlor Team</a>" >< res ) {
    version = "unknown";
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"froxlor/detected", value:TRUE );
    set_kb_item( name:"froxlor/http/detected", value:TRUE );

    cpe = "cpe:/a:froxlor:froxlor";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Froxlor", version:version, install:install, cpe:cpe,
                                              concludedUrl:conclUrl ),
                 port:port );
  }
}

exit( 0 );
