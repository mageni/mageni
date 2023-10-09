# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111036");
  script_version("2023-09-06T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-06 05:05:19 +0000 (Wed, 06 Sep 2023)");
  script_tag(name:"creation_date", value:"2015-09-07 12:00:00 +0200 (Mon, 07 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Red Hat/JBoss WildFly Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.wildfly.org/");

  script_tag(name:"summary", value:"HTTP based detection of Red Hat/JBoss WildFly.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:8080 );
banner = http_get_remote_headers( port:port );

url = "/";
version = "unknown";
detected = FALSE;

# server: WildFly/10
# Server: WildFly/10
# Server: WildFly/11
if( concl = eregmatch( string:banner, pattern:"[Ss]erver\s*:\s*WildFly[ /]?([0-9.]+)?", icase:FALSE ) ) {

  detected = TRUE;

  conclurl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  concluded = "  " + concl[0];
  if( concl[1] )
    version = concl[1];
}

buf = http_get_cache( item:url, port:port );

# <h1>Welcome to WildFly 8</h1>
# <title>Welcome to WildFly Application Server 8</title>
# <h3>Your WildFly 8 is running.</h3>
# <title>Welcome to WildFly</title>
# <h1>Welcome to WildFly</h1>
# <h3>Your WildFly instance is running.</h3>
# <title>Welcome to WildFly Application Server</title>
# <h3>Your WildFly Application Server is running.</h3>
if( concl = eregmatch( string:buf, pattern:"<(h[0-9]+|title)>(Welcome to|Your) WildFly( Application Server)?\s*([0-9.]+)?", icase:FALSE ) ) {

  detected = TRUE;

  # nb: Don't add the same "/" URL twice
  if( ! conclurl )
    conclurl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  if( concluded )
    concluded += '\n';
  concluded += "  " + concl[0];

  if( version == "unknown" && concl[4] )
    version = concl[4];
}

url = "/documentation.html";
buf = http_get_cache( item:url, port:port );

# <title>WildFly 8 Documentation</title>
# <title>WildFly 11 Documentation</title>
if( concl = eregmatch( string:buf, pattern:">WildFly( Application Server)?\s+([0-9.]+)?\s*Documentation", icase:FALSE ) ) {

  detected = TRUE;

  if( conclurl )
    conclurl += '\n';
  conclurl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  if( concluded )
    concluded += '\n';
  concluded += "  " + concl[0];

  if( version == "unknown" && concl[2] )
    version = concl[2];
}

url = "/error/index_win.html";
buf = http_get_cache( item:url, port:port );

# nb: Pattern / strings on this page are similar/same to the ones on the "/" index page
if( concl = eregmatch( string:buf, pattern:"<(h[0-9]+|title)>(Welcome to|Your) WildFly( Application Server)?\s*([0-9.]+)?", icase:FALSE ) ) {

  detected = TRUE;

  if( conclurl )
    conclurl += '\n';
  conclurl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  if( concluded )
    concluded += '\n';
  concluded += "  " + concl[0];

  if( version == "unknown" && concl[4] )
    version = concl[4];
}

if( detected ) {

  install = port + "/tcp";

  set_kb_item( name:"redhat/wildfly/detected", value:TRUE );
  set_kb_item( name:"redhat/wildfly/http/detected", value:TRUE );

  # nb: Just some generic KB keys for active checks as WildFly might be affected the same way as
  # other JBoss products...
  set_kb_item( name:"redhat/jboss/prds/detected", value:TRUE );
  set_kb_item( name:"redhat/jboss/prds/http/detected", value:TRUE );

  cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:redhat:wildfly:" );
  cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:redhat:jboss_wildfly_application_server:" );
  if( ! cpe1 ) {
    cpe1 = "cpe:/a:redhat:wildfly";
    cpe2 = "cpe:/a:redhat:jboss_wildfly_application_server";
  }

  register_product( cpe:cpe1, location:install, port:port, service:"www" );
  register_product( cpe:cpe2, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Red Hat/JBoss WildFly",
                                            version:version,
                                            install:install,
                                            cpe:cpe1,
                                            concludedUrl:conclurl,
                                            concluded:concluded ),
               port:port );
}

exit( 0 );
