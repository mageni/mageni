# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111093");
  script_version("2023-09-08T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-09-08 05:06:21 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"creation_date", value:"2016-04-06 07:12:12 +0200 (Wed, 06 Apr 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Axis Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"HTTP based detection of the Apache Axis SOAP stack.");

  script_xref(name:"URL", value:"https://axis.apache.org/axis/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8080 );

foreach dir( make_list_unique( "/axis", "/imcws", "/WebServiceImpl", "/dswsbobje", "/ws", http_cgi_dirs( port:port ) ) ) {

  found = FALSE;
  install = dir;

  if( dir == "/" )
    dir = "";

  if( dir == "/services" )
    continue; # This would create a duplicated detection at / and /services

  #Version service
  url = dir + "/services/Version?method=getVersion";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  #Second check just to be safe
  url2 = dir + "/services/non-existent";
  req2 = http_get( item:url2, port:port );
  buf2 = http_keepalive_send_recv( port:port, data:req2 );

  #Index page
  url3 = dir + "/index.jsp";
  buf3 = http_get_cache( item:url3, port:port );

  if( "<h2>AXIS error</h2>" >< buf2 || "No service is available at this URL" >< buf2 ||
      "<h1>Axis HTTP Servlet</h1>" >< buf2 ) {
    conclUrl = http_report_vuln_url( url:url2, port:port, url_only:TRUE );
    found = TRUE;
  }
  else if ( "Apache Axis version:" >< buf ||
            "The AXIS engine could not find a target service to invoke!" >< buf ||
            "<h1>Axis HTTP Servlet</h1>" >< buf ) {
    conclUrl = http_report_vuln_url( url:url, port:port, url_only:TRUE );
    found = TRUE;
  }
  else if( "<title>Apache-Axis</title>" >< buf3 || "Apache-AXIS</h1>" >< buf3 ) {
    conclUrl = http_report_vuln_url( url:url3, port:port, url_only:TRUE );
    found = TRUE;
  }

  if( found ) {

    version = "unknown";
    ver = eregmatch( string:buf, pattern:"Apache Axis version: ([0-9.]+)" );

    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      conclUrl = http_report_vuln_url( url:url, port:port, url_only:TRUE );
    }

    url = dir + "/servlet/AxisServlet";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "<h2>And now... Some Services</h2>" >< buf ) {
      extra += http_report_vuln_url( url:url, port:port, url_only:TRUE ) + ' lists available web services\n';
    }

    # Second try to get exposed web services
    url = dir + "/services";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "<h2>And now... Some Services</h2>" >< buf ) {
      extra += http_report_vuln_url( url:url, port:port, url_only:TRUE ) + ' lists available web services\n';
    }

    url = dir + "/happyaxis.jsp";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "<title>Axis Happiness Page</title>" >< buf || "Examining webapp configuration" >< buf ) {
      extra += http_report_vuln_url( url:url, port:port, url_only:TRUE ) + ' exposes the system configuration\n';
    }

    url = dir + "/services/AdminService?wsdl";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "AdminServiceResponse" >< buf || "AdminServiceRequest" >< buf ) {
      extra += http_report_vuln_url( url:url, port:port, url_only:TRUE ) + ' exposes the AdminService\n';

      # If version wasn't identified yet try to get it from this service
      if( version == "unknown" ) {
        ver = eregmatch( string:buf, pattern:"Apache Axis version: ([0-9.]+)" );
        if( ! isnull( ver[1] ) ) {
          version = ver[1];
          conclUrl = http_report_vuln_url( url:url, port:port, url_only:TRUE );
        }
      }
    }

    url = dir + "/EchoHeaders.jws?wsdl";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "whoamiResponse" >< buf || "echoResponse" >< buf ) {
      extra += http_report_vuln_url( url:url, port:port, url_only:TRUE ) + ' exposes the EchoHeaders default webservice\n';

      # If version wasn't identified yet try to get it from this service
      if( version == "unknown" ) {
        ver = eregmatch( string:buf, pattern:"Apache Axis version: ([0-9.]+)" );
        if( ! isnull( ver[1] ) ) {
          version = ver[1];
          conclUrl = http_report_vuln_url( url:url, port:port, url_only:TRUE );
        }
      }
    }

    url = dir + "/SOAPMonitor";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "SOAPMonitorApplet.class" >< buf ) {
      extra += http_report_vuln_url( url:url, port:port, url_only:TRUE ) + ' expostes the SOAPMonitor Page\n';
    }

    url = dir + "/servlet/AdminServlet";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "<title>Axis</title>" >< buf || "Server is running" >< buf ) {
      extra += http_report_vuln_url( url:url, port:port, url_only:TRUE ) + ' exposes the AdminServlet\n';
    }

    url = dir + "/servlet/MyServlet";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "<title>Axis</title>" >< buf || "Server is running" >< buf ) {
      extra += http_report_vuln_url( url:url, port:port, url_only:TRUE ) + ' exposes the MyServlet\n';
    }

    set_kb_item( name:"apache/axis/detected", value:TRUE );
    set_kb_item( name:"apache/axis/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:apache:axis:" );
    if( ! cpe )
      cpe = "cpe:/a:apache:axis";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Apache Axis",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0],
                                              concludedUrl:conclUrl,
                                              extra:extra ),
                 port:port );
  }
}

exit( 0 );
