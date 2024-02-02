# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801102");
  script_version("2023-11-24T16:09:32+0000");
  script_tag(name:"last_modification", value:"2023-11-24 16:09:32 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2009-09-10 15:23:12 +0200 (Thu, 10 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Adobe RoboHelp Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.adobe.com/products/robohelp/robohelp-server.html");

  script_tag(name:"summary", value:"HTTP based detection of Adobe RoboHelp Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:8080 );

foreach dir( make_list_unique( "/robohelp", "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/admin/login.jsp";
  res = http_get_cache( item:url, port:port );

  # <title>RoboHelp Server Login</title>
  if( res =~ "^HTTP/1\.[01] 200" && "RoboHelp Server Login" >< res ) {

    conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    version = "unknown";

    # strFlashVars += "&gsVersion=8.0";
    ver = eregmatch( pattern:"Version=([0-9.]+)", string:res );
    if( ! isnull( ver[1] ) )
      version = ver[1];

    set_kb_item( name:"adobe/robohelp/server/detected", value:TRUE );
    set_kb_item( name:"adobe/robohelp/server/http/detected", value:TRUE );

    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:adobe:robohelp_server:" );
    if( ! cpe )
      cpe = "cpe:/a:adobe:robohelp_server";

    # nb: Seems to only run on Windows
    os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", desc:"Adobe RoboHelp Server Detection (HTTP)", runs_key:"windows" );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Adobe RoboHelp Server",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclurl,
                                              concluded:ver[0] ),
                 port:port );
  }
}

exit( 0 );
