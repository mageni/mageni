# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900932");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-08-04T05:06:23+0000");
  script_tag(name:"last_modification", value:"2023-08-04 05:06:23 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("OXID eShop Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of OXID eShop.");

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

if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/oxid", "/eshop", "/oxid-eshop", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" )
    dir = "";

  res = http_get_cache( item: dir + "/admin/", port:port );

  if( "OXID eShop Login" >< res && res =~ "OXID eShop (Enterprise|Professional|Community)" ) {
    version = "unknown";

    # Just major version e.g. OXID eShop Enterprise Edition, Version 6
    ver = eregmatch( pattern:"Version ([0-9.]+)", string:res );
    if( ! isnull( ver[1] ) )
      version = ver[1];

    ed = eregmatch( pattern:"OXID eShop (Enterprise|Professional|Community)", string:res );
    if( ! isnull( ed[1] ) ) {
      edition = ed[1];
      set_kb_item( name:"oxid_eshop/edition", value:edition );
    }

    set_kb_item(name: "oxid_eshop/detected", value: TRUE);

    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:oxid:eshop:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:oxid:eshop";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"OXID eShop " + edition + " Edition", version:version,
                                              install:install, cpe:cpe, concluded:ver[0] ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
