# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103918");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-03-13 10:13:17 +0100 (Thu, 13 Mar 2014)");
  script_name("Artifactory Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
 to extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/artifactory", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/webapp/home.html?0";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );
  if( buf == NULL ) continue;

  if( "Artifactory is happily serving" >< buf && "<title>Artifactory" >< buf)
  {

    vers = "unknown";
    version = eregmatch( string: buf, pattern: '<span class="version">Artifactory ([0-9.]+)',icase:TRUE );

    if ( ! isnull( version[1] ) ) vers = chomp( version[1] );

    set_kb_item(name: string( "www/", port, "/artifactory" ), value: string( vers," under ",install + '/webapp') );
    set_kb_item(name:"artifactory/installed",value:TRUE);

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:jfrog:artifactory:" );
    if( isnull( cpe ) ) cpe = "cpe:/a:jfrog:artifactory";

    register_product( cpe:cpe, location:install + "/webapp/", port:port, service:"www" );

    log_message( data: build_detection_report( app:"Artifactory",
                                               version:vers,
                                               install:install + "/webapp/",
                                               cpe:cpe,
                                               concluded: version[0] ),
                 port:port );
  }
}

exit(0);
