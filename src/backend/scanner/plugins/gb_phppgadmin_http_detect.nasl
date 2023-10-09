# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103294");
  script_version("2023-09-29T05:05:51+0000");
  script_tag(name:"last_modification", value:"2023-09-29 05:05:51 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"creation_date", value:"2011-10-12 15:33:11 +0200 (Wed, 12 Oct 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("phpPgAdmin Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of phpPgAdmin.");

  script_xref(name:"URL", value:"https://github.com/phppgadmin/phppgadmin");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/phpPgAdmin", "/pgadmin", "/phppgadmin", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/intro.php";
  buf = http_get_cache( item:url, port:port );
  if( ! buf )
    continue;

  if( egrep( pattern:"<title>phpPgAdmin</title>", string:buf, icase:TRUE ) ) {
    version = "unknown";
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( string:buf, pattern:"<h1>phpPgAdmin ([0-9.]+)", icase:TRUE );
    if( ! isnull( vers[1] ) )
      version = vers[1];

    set_kb_item( name:"phppgadmin/detected", value:TRUE );
    set_kb_item( name:"phppgadmin/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:phppgadmin:phppgadmin:" );
    if ( ! cpe )
      cpe = "cpe:/a:phppgadmin:phppgadmin";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"phpPgAdmin", version:version, install:install, cpe:cpe,
                                              concluded:vers[0], concludedUrl:conclUrl ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
