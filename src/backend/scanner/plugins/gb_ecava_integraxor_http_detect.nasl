# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804298");
  script_version("2024-01-09T05:06:46+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2014-05-19 16:21:28 +0530 (Mon, 19 May 2014)");
  script_name("ECAVA IntegraXor Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 7131);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ECAVA IntegraXor.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:7131 );

foreach dir( make_list_unique( "/", "/DEM0", "/project", "/ecava", "/integraxor", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  res = http_get_cache( item:dir + "/res?res/igres.dll/sys_about.html", port:port );
  res2 = http_get_cache( item:dir + "/index.html", port:port );

  if( ">Powered by IntegraXor" >< res || "<title>ECAVA IntegraXor</title>" >< res2 || "system/scripts/igrX.js" >< res2 ) {

    version = "unknown";

    ver = eregmatch( pattern:">Version:.*>(IGX )?([0-9.]+)", string:res );
    if( ver[2] )
      version = ver[2];

    set_kb_item( name:"ecava/integraxor/detected", value:TRUE );
    set_kb_item( name:"ecava/integraxor/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ecava:integraxor:" );
    if( ! cpe )
      cpe = "cpe:/a:ecava:integraxor";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"ECAVA IntegraXor",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                 port:port );
  }
}

exit( 0 );
