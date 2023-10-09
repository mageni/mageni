# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# SPDX-FileCopyrightText: Reworked detection methods / pattern / code since 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apache:axis2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111008");
  script_version("2023-10-09T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-10-09 05:05:36 +0000 (Mon, 09 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-03-20 08:00:00 +0100 (Fri, 20 Mar 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache Axis2 Web Services Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("gb_apache_axis2_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/axis2/http/detected");

  script_xref(name:"URL", value:"https://axis.apache.org/axis2/java/core/");
  script_xref(name:"URL", value:"https://axis.apache.org/axis2/c/core/");

  script_tag(name:"summary", value:"HTTP based detection of Apache Axis2 Web Services.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

function axis2_extract_services( port, url, data, pattern, sep ) {

  local_var port, url, data, pattern, sep;
  local_var services, _service, service_info, report;

  if( ! services = egrep( string:data, pattern:pattern, icase:FALSE ) )
    return;

  foreach _service( split( services, sep:sep ) ) {

    service_info = eregmatch( string:_service, pattern:pattern, icase:FALSE );
    if( ! isnull( service_info[2] ) ) {

      # nb: For the second and third case this already includes the "full" URL like e.g.:
      # /axis2/services/Version
      # For the first case this *might* be empty if an relative URL is used (which was the case on
      # all tested systems / versions)
      service_url = service_info[1];
      service_name = service_info[2];

      # For the first 'dir + "/services/"' case tested below the "full" URL is usually not included
      # in the service name (unlike the other cases) due to a relative URL in the HTML source code.
      # For this case we need to append the "url" part here and checking if it isn't already
      # included (e.g. there might be special cases where the URL is an absolute one).
      if( url ) {
        if( url >!< service_url )
          service_url = url + service_url;
        service_url += service_name;
      }

      set_kb_item( name:"apache/axis2/webservices/http/" + port + "/list", value:service_url );

      # nb: In all cases we currently need to append the "?wsdl" in the reporting as otherwise the
      # end user will get an error if opening the URL in e.g. the browser. But this is only done for
      # the reporting here as VTs using the service_url above might need to append something else
      # like e.g. ?xsd=
      report += '\n - ' + service_name + " (URL: " + service_url + "?wsdl)";
    }
  }

  return report;
}

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

found_services = FALSE;

# nb:
# - Currently unclear why some systems are using various of these different endpoints with largely
#   different output. The version, the deployment variant or the implementation (Axis2/Java vs.
#   Axis2/C) might play a role here...
# - We're trying each URL separately just to be sure to catch all variants

url = dir + "/services/";
buf = http_get_cache( item:url, port:port );

if( buf && buf =~ "^HTTP/1\.[01] 200" && "<title>Axis2: Services</title>" >< buf ) {

  # e.g. (everything in one line):
  # <html><head><title>Axis2: Services</title></head><body><h2>Deployed services</h2><h3><a href="MSGUI?wsdl">MSGUI</a></h3>Available operations <ul><li>requestOperation</li></ul></body></html>
  # <html><head><title>Axis2: Services</title></head><body><h2>Deployed services</h2><h3><a href="EventService?wsdl">EventService</a></h3>Available operations <ul><li>getAlarmLogs2</li><li>closeEvent3</li><li>getEvent2</li><li>getEventsAttachment2</li><li>getEvents2</li></ul>
  pattern = '<a href="(' + url + ')?(.+)\\?wsdl">';
  sep = '?wsdl">';

  if( report = axis2_extract_services( port:port, url:url, data:buf, pattern:pattern, sep:sep ) ) {
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    found_services = TRUE;
  }
}

if( ! found_services ) {

  url = dir + "/services/listServices";
  buf = http_get_cache( item:url, port:port );

  if( buf && buf =~ "^HTTP/1\.[01] 200" && ( "<title>Axis2: Services</title>" >< buf || "<title>List Services</title>" >< buf ) ) {

    # On 1.8.2:
    #
    # <h2><a style="color:blue" href="http://localhost:8080/axis2/services/Version?wsdl">Version</a></h2>
    #
    # <h5>Service Description : <span style="color:black;">
    #         This service is to get the running Axis version
    #     </span></h5>
    # <h5>Service EPR : http://localhost:8080/axis2/services/Version</h5>
    # <h5>Service Status : Active</h5><br>
    # <i>Available Operations</i><ul><li>getVersion</li>
    #
    # Seen on some (custom?) 1.7.2:
    #
    # <h2><a style="color:blue" href="http://<redacted>/axis2/services/ExtensionService?wsdl">ExtensionService</a></h2>
    #
    #
    # <h5>Service Description : <span style="color:black;">ExtensionService</span></h5>
    # <h5>Service EPR : http://<redacted>/axis2/services/ExtensionService</h5>
    # <h5>Service Status : Active</h5><br>
    # <i>Available Operations</i><ul><li>getCommentsByUser</li>
    #
    # On 1.4.1 and 1.5:
    #
    # <h2><font color="blue"><a href="http://localhost:8080/axis2/services/Version?wsdl">Version</a></font></h2>
    # <font color="blue">Service EPR : </font><font color="black">http://localhost:8080/axis2/services/Version</font><br>
    #
    #
    # <h4>Service Description : <font color="black">Version</font></h4>
    # <i><font color="blue">Service Status : Active</font></i><br>
    # <i>Available Operations</i><ul><li>getVersion</li>
    #
    pattern = ">Service EPR\s*:.+(" + dir + "/services/([^<]+))</";
    sep = '\n';

    if( report = axis2_extract_services( port:port, data:buf, pattern:pattern, sep:sep ) ) {
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      found_services = TRUE;
    }
  }
}

if( ! found_services ) {

  # nb:
  # - Needed for Axis2 0.93 and below
  # - The service acts quite wired, we first need to query this page, get a valid cookie and then
  #   query the second URL. Otherwise we're only getting something like the following on both URLs:
  #   "There seems to be no services listed! Try hitting refresh"
  url1 = dir + "/listServices";

  # nb: No http_get_cache() here as we need a "fresh" cookie
  req = http_get( item:url1, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  cookie = eregmatch( pattern:"(JSESSIONID=[0-9a-zA-Z]+);", string:buf );
  if( cookie[1] )
    headers = make_array( "Cookie", cookie[1] );

  url2 = url1 + ".jsp";
  req = http_get_req( port:port, url:url2, add_headers:headers );
  buf = http_keepalive_send_recv( port:port, data:req );

  if( buf && buf =~ "^HTTP/1\.[01] 200" && "<title>List Services</title>" >< buf ) {

    # On 0.93:
    #
    #      <h2><font color="blue"><a href="http://localhost:8080/axis2/services/version?wsdl">version</a></font></h2>
    #            <font color="blue">Service EPR : <font color="black">http://localhost:8080/axis2/services/version</font>
    #            <h4>Service Description : <font color="black">
    #         This service is to get the running Axis version
    #     </h4>
    #            <i>Available operations</i><ul><li>getVersion</li>
    pattern = ">Service EPR\s*:.+(" + dir + "/services/([^<]+))</";
    sep = '\n';

    if( report = axis2_extract_services( port:port, data:buf, pattern:pattern, sep:sep ) ) {
      conclUrl = http_report_vuln_url( port:port, url:url1, url_only:TRUE ) + " / " + http_report_vuln_url( port:port, url:url2, url_only:TRUE );
      found_services = TRUE;
    }
  }
}

if( ! found_services )
  exit( 0 );

report = "The following services were detected at '" + conclUrl + "':" + report;
set_kb_item( name:"apache/axis2/webservices/detected", value:TRUE );
set_kb_item( name:"apache/axis2/webservices/" + port + "/detected", value:TRUE );
set_kb_item( name:"apache/axis2/webservices/http/detected", value:TRUE );
set_kb_item( name:"apache/axis2/webservices/http/" + port + "/detected", value:TRUE );
log_message( port:port, data:report );

exit( 0 );
