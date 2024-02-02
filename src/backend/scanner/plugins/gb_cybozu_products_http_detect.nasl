# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902533");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Cybozu Products Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of various Cybozu products.");

  script_tag(name:"insight", value:"The following Cybozu products are currently detected:

  - Cybozu Garoon

  - Cybozu Office

  - Cybozu Dezie

  - Cybozu MailWise");

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

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/scripts", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  foreach path( make_list( "", "/cbgrn", "/garoon", "/grn" ) ) {

    # nb: Don't run the ".exe" checks against Linux systems
    if( os_host_runs( "Linux" ) == "yes" )
      break;

    install = dir + path;

    res = http_get_cache( item: install + "/grn.exe", port:port );

    if( res =~ "^HTTP/1\.[01] 200" && "Cybozu" >< res && "Garoon" >< res ) {

      version = "unknown";

      ver = eregmatch( pattern:"Version ([0-9.]+)", string:res );
      if( ver[1] )
        version = ver[1];

      set_kb_item( name:"cybozu/garoon/detected", value:TRUE );
      set_kb_item( name:"cybozu/garoon/http/detected", value:TRUE );
      set_kb_item( name:"cybozu/products/detected", value:TRUE );
      set_kb_item( name:"cybozu/products/http/detected", value:TRUE );

      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cybozu:garoon:" );
      if( ! cpe )
        cpe = "cpe:/a:cybozu:garoon";

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"Cybozu Garoon",
                                                version:version,
                                                install:install,
                                                cpe:cpe,
                                                concluded:ver[0] ),
                   port:port );
    }
  }

  foreach path( make_list( "", "/cbag", "/office", "/cgi-bin/cbag" ) ) {

    foreach file( make_list( "/ag.exe", "/ag.cgi" ) ) {

      # nb: Don't run the ".exe" checks against Linux systems
      if( file == "/ag.exe" && os_host_runs( "Linux" ) == "yes" )
        continue;

      install = dir + path;

      res = http_get_cache( item:install + file, port:port );

      if( res =~ "^HTTP/1\.[01] 200" && "Cybozu" >< res && "Office" >< res ) {

        version = "unknown";

        ver = eregmatch( pattern:"Office Version ([0-9.]+)", string:res );
        if( ver[1] )
          version = ver[1];

        set_kb_item( name:"cybozu/office/detected", value:TRUE );
        set_kb_item( name:"cybozu/office/http/detected", value:TRUE );
        set_kb_item( name:"cybozu/products/detected", value:TRUE );
        set_kb_item( name:"cybozu/products/http/detected", value:TRUE );

        cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cybozu:office:" );
        if( ! cpe )
          cpe = "cpe:/a:cybozu:office";

        register_product( cpe:cpe, location:install, port:port, service:"www" );

        log_message( data:build_detection_report( app:"Cybozu Office",
                                                  version:version,
                                                  install:install,
                                                  cpe:cpe,
                                                  concluded:ver[0] ),
                     port:port );
      }
    }
  }

  foreach path( make_list( "", "/cbdb", "/dezie" ) ) {

    # nb: Don't run the ".exe" checks against Linux systems
    if( os_host_runs( "Linux" ) == "yes" )
      break;

    install = dir + path;

    res = http_get_cache( item:install + "/db.exe", port:port );

    if( res =~ "^HTTP/1\.[01] 200" && "Cybozu" >< res && "Dezie" >< res ) {

      version = "unknown";

      ver = eregmatch( pattern:"Version ([0-9.]+)", string:res );
      if( ver[1] )
        version = ver[1];

      set_kb_item( name:"cybozu/dezie/detected", value:TRUE );
      set_kb_item( name:"cybozu/dezie/http/detected", value:TRUE );
      set_kb_item( name:"cybozu/products/detected", value:TRUE );
      set_kb_item( name:"cybozu/products/http/detected", value:TRUE );

      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cybozu:dezie:" );
      if( ! cpe )
        cpe = "cpe:/a:cybozu:dezie";

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"Cybozu Dezie",
                                                version:version,
                                                install:install,
                                                cpe:cpe,
                                                concluded:ver[0] ),
                   port:port );
    }
  }

  foreach path( make_list( "", "/cbmw", "/mailwise" ) ) {

    # nb: Don't run the ".exe" checks against Linux systems
    if( os_host_runs( "Linux" ) == "yes" )
      break;

    install = dir + path;

    res = http_get_cache( item:install + "/mw.exe", port:port );

    if( res =~ "^HTTP/1\.[01] 200" && "Cybozu" >< res && "mailwise" >< res ) {

      version = "unknown";

      ver = eregmatch( pattern:"Version ([0-9.]+)", string:res );
      if( ver[1] )
        version = ver[1];

      set_kb_item( name:"cybozu/mailwise/detected", value:TRUE );
      set_kb_item( name:"cybozu/mailwise/http/detected", value:TRUE );
      set_kb_item( name:"cybozu/products/detected", value:TRUE );
      set_kb_item( name:"cybozu/products/http/detected", value:TRUE );

      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cybozu:mailwise:" );
      if( ! cpe )
        cpe = "cpe:/a:cybozu:mailwise";

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"Cybozu MailWise",
                                                version:version,
                                                install:install,
                                                cpe:cpe,
                                                concluded:ver[0] ),
                   port:port );
    }
  }
}

exit( 0 );
