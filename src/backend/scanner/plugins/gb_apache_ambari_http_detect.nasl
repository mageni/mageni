# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808648");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-09 18:35:29 +0530 (Tue, 09 Aug 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Ambari Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache Ambari.");

  script_xref(name:"URL", value:"https://ambari.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8080 );

url = "/javascripts/app.js";

req = http_get_req( port:port, url:url, add_headers:make_array( "Accept-Encoding", "gzip, deflate" ) );
res = http_keepalive_send_recv( port:port, data:req );

if( res =~ "HTTP/1\.[01] 200" && "Ambari" >< res && res =~ "Licensed under the Apache License" ) {

  version = "unknown";
  install = "/";
  conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  # Ambari has three digits version codes but the App.version contains something like 2.5.0.3 where .3 doesn't match the actual version (internal version number?)
  vers = eregmatch( pattern:"App.version = '([0-9]\.[0-9]\.[0-9])(\.[0-9.])?';", string:res );
  if( ! isnull( vers[1] ) )
    version = vers[1];

  set_kb_item( name:"apache/ambari/detected", value:TRUE );
  set_kb_item( name:"apache/ambari/http/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:apache:ambari:" );
  if( ! cpe )
    cpe = "cpe:/a:apache:ambari";

  os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, runs_key:"unixoide",
                          desc:"Apache Ambari Detection (HTTP)" );

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Apache Ambari", version:version, install:install,
                                            cpe:cpe, concludedUrl:conclUrl, concluded:vers[0] ),
               port:port );
  exit( 0 );
}

exit( 0 );
