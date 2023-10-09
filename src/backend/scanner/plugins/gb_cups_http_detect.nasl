# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900348");
  script_version("2023-08-16T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-08-16 05:05:28 +0000 (Wed, 16 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("CUPS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 631);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Common Unix Printing System (CUPS).");

  script_xref(name:"URL", value:"https://www.cups.org/");
  script_xref(name:"URL", value:"https://github.com/OpenPrinting/cups");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:631 );

res = http_get_cache( port:port, item:"/" );

# Server: CUPS/1.1
# <TITLE>Forbidden - CUPS v2.4.6</TITLE>
if( "Server: CUPS/" >< res || res =~ "<TITLE>(Forbidden|Home|Not Found|Bad Request) - CUPS.*</TITLE>" ) {

  version = "unknown";
  install = "/";

  ver = eregmatch( pattern:"<title>.*CUPS v?([0-9.RCB]+).*</title>", string:res, icase:TRUE );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
  } else {
    ver = eregmatch( pattern:"Server: CUPS/([0-9.RCB]+)", string:res, icase:TRUE );
    if( ! isnull( ver[1] ) )
      version = ver[1]; # Only getting the major version here
  }

  set_kb_item( name:"cups/detected", value:TRUE );
  set_kb_item( name:"cups/http/detected", value:TRUE );

  # nb: CUPS for Mac is developed by Apple, while for Linux and other platforms by OpenPrinting, since 2020.
  cpe1 = build_cpe( value:version, exp:"^([0-9.]+)([a-z0-9]+)?", base:"cpe:/a:apple:cups:" );
  cpe2 = build_cpe( value:version, exp:"^([0-9.]+)([a-z0-9]+)?", base:"cpe:/a:openprinting:cups:" );
  if( ! cpe1 ) {
    cpe1 = "cpe:/a:apple:cups";
    cpe2 = "cpe:/a:openprinting:cups";
  }

  register_product( cpe:cpe1, location:install, port:port, service:"www" );
  register_product( cpe:cpe2, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"CUPS",
                                            version:version,
                                            install:install,
                                            port:port,
                                            cpe:cpe1,
                                            concluded:ver[0] ),
                                            port:port );
}

exit( 0 );
