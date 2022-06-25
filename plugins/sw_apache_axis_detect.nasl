###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_apache_axis_detect.nasl 11020 2018-08-17 07:35:00Z cfischer $
#
# Apache Axis Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111093");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11020 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:35:00 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-04-06 07:12:12 +0200 (Wed, 06 Apr 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache Axis Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"This host is running the Apache Axis SOAP stack.");

  script_xref(name:"URL", value:"https://axis.apache.org/axis/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:8080 );

foreach dir( make_list_unique( "/axis", "/imcws", "/WebServiceImpl", "/dswsbobje", "/ws", cgi_dirs( port:port ) ) ) {

  found = FALSE;
  install = dir;
  if( dir == "/" ) dir = "";
  if( dir == "/services" ) continue; # This would create a duplicated detection at / and /services

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
    conclUrl = report_vuln_url( url:url2, port:port, url_only:TRUE );
    found = TRUE;
  } else if ( "Apache Axis version:" >< buf || "The AXIS engine could not find a target service to invoke!" >< buf ||
              "<h1>Axis HTTP Servlet</h1>" >< buf ) {
    conclUrl = report_vuln_url( url:url, port:port, url_only:TRUE );
    found = TRUE;
  } else if( "<title>Apache-Axis</title>" >< buf3 || "Apache-AXIS</h1>" >< buf3 ) {
    conclUrl = report_vuln_url( url:url3, port:port, url_only:TRUE );
    found = TRUE;
  }

  if( found ) {

    version = "unknown";
    ver = eregmatch( string:buf, pattern:"Apache Axis version: ([0-9.]+)" );

    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      conclUrl = report_vuln_url( url:url, port:port, url_only:TRUE );
    }

    url = dir + "/servlet/AxisServlet";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "<h2>And now... Some Services</h2>" >< buf ) {
      extra += report_vuln_url( url:url, port:port, url_only:TRUE ) + ' lists available web services\n';
    }

    # Second try to get exposed web services
    url = dir + "/services";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "<h2>And now... Some Services</h2>" >< buf ) {
      extra += report_vuln_url( url:url, port:port, url_only:TRUE ) + ' lists available web services\n';
    }

    url = dir + "/happyaxis.jsp";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "<title>Axis Happiness Page</title>" >< buf || "Examining webapp configuration" >< buf ) {
      extra += report_vuln_url( url:url, port:port, url_only:TRUE ) + ' exposes the system configuration\n';
    }

    url = dir + "/services/AdminService?wsdl";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "AdminServiceResponse" >< buf || "AdminServiceRequest" >< buf ) {
      extra += report_vuln_url( url:url, port:port, url_only:TRUE ) + ' exposes the AdminService\n';

      # If version wasn't identified yet try to get it from this service
      if( version == "unknown" ) {
        ver = eregmatch( string:buf, pattern:"Apache Axis version: ([0-9.]+)" );
        if( ! isnull( ver[1] ) ) {
          version = ver[1];
          conclUrl = report_vuln_url( url:url, port:port, url_only:TRUE );
        }
      }
    }

    url = dir + "/EchoHeaders.jws?wsdl";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "whoamiResponse" >< buf || "echoResponse" >< buf ) {
      extra += report_vuln_url( url:url, port:port, url_only:TRUE ) + ' exposes the EchoHeaders default webservice\n';

      # If version wasn't identified yet try to get it from this service
      if( version == "unknown" ) {
        ver = eregmatch( string:buf, pattern:"Apache Axis version: ([0-9.]+)" );
        if( ! isnull( ver[1] ) ) {
          version = ver[1];
          conclUrl = report_vuln_url( url:url, port:port, url_only:TRUE );
        }
      }
    }

    url = dir + "/SOAPMonitor";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "SOAPMonitorApplet.class" >< buf ) {
      extra += report_vuln_url( url:url, port:port, url_only:TRUE ) + ' expostes the SOAPMonitor Page\n';
    }

    url = dir + "/servlet/AdminServlet";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "<title>Axis</title>" >< buf || "Server is running" >< buf ) {
      extra += report_vuln_url( url:url, port:port, url_only:TRUE ) + ' exposes the AdminServlet\n';
    }

    url = dir + "/servlet/MyServlet";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "<title>Axis</title>" >< buf || "Server is running" >< buf ) {
      extra += report_vuln_url( url:url, port:port, url_only:TRUE ) + ' exposes the MyServlet\n';
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/axis", value:tmp_version );
    set_kb_item( name:"axis/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"([0-9.]+)", base:'cpe:/a:apache:axis:' );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:apache:axis';

    register_product( cpe:cpe, location:install, port:port );

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
