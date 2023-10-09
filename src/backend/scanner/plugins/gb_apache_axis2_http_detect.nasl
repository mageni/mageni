# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100813");
  script_version("2023-10-09T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-10-09 05:05:36 +0000 (Mon, 09 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache Axis2 Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache Axis2, a Web Services / SOAP /
  WSDL engine, the successor to the widely used Apache Axis SOAP stack.");

  script_xref(name:"URL", value:"https://axis.apache.org/axis2/java/core/");
  script_xref(name:"URL", value:"https://axis.apache.org/axis2/c/core/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:8080 );
banner = http_get_remote_headers( port:port );

if( banner && egrep( string:banner, pattern:"^[Ss]erver\s*:\s*Simple-Server", icase:FALSE ) ) {
  # nb: Axis2 running on binary distribution, no need to iterate over all other directories...
  dirs = make_list( "/axis2" );
} else {
  # nb: Axis2 running on Tomcat or similar application servers
  dirs = make_list_unique(
    "/axis2",           # Standard one
    "/imcws",           # SAP Business Objects 12 and/or 3com IMC (See CVE-2010-2103)
    "/WebServiceImpl",  # Computer Associates ARCserve D2D r15 Web Service (See CVE-2010-0219 / https://www.exploit-db.com/exploits/15869)
    "/dswsbobje",       # SAP BusinessObjects Enterprise XI 3.2 (See CVE-2010-0219)
    "/ws",              # Currently unknown
    "/MicroStrategyWS", # Microstrategy Web 10.4 (See CVE-2020-11450)
    http_cgi_dirs( port:port ) );
}

foreach dir( dirs ) {

  detected = FALSE;

  install = dir;
  if( dir == "/" )
    dir = "";

  # nb: Version service on newer Axis2 versions
  url1 = dir + "/services/Version/getVersion";
  buf1 = http_get_cache( item:url1, port:port );

  # nb: Admin interface for < 1.8.x
  url2 = dir + "/axis2-admin/";
  buf2 = http_get_cache( item:url2, port:port );

  # nb: Overview page
  url3 = dir + "/axis2-web/index.jsp";
  buf3 = http_get_cache( item:url3, port:port );

  # nb: Old location of Version service for Axis2 0.93 and below
  url4 = dir + "/services/version/getVersion";
  buf4 = http_get_cache( item:url4, port:port );

  # nb: "Happyness" page for 1.x
  url5 = dir + "/axis2-web/HappyAxis.jsp";
  buf5 = http_get_cache( item:url5, port:port );

  # nb: Admin interface for >= 1.8.x
  url6 = dir + "/axis2-admin/welcome";
  buf6 = http_get_cache( item:url6, port:port );

  # nb: "Happyness" page for 0.9x
  url7 = dir + "/HappyAxis.jsp";
  buf7 = http_get_cache( item:url7, port:port );

  # nb: Admin interface for 0.9x
  url8 = dir + "/Login.jsp";
  buf8 = http_get_cache( item:url8, port:port );

  # nb: Another "landing" page
  url9 = dir + "/";
  buf9 = http_get_cache( item:url9, port:port );

  if( buf1 =~ "Hello I am Axis2" ||
     ( "getVersionResponse" >< buf1 && "the Axis2 version is" >< buf1 ) ||
     "The system is attempting to access an inactive service: Version" >< buf1 ||
     "The service cannot be found for the endpoint reference (EPR)" >< buf1 ||
     "Service Not found EPR is" >< buf1 ) {
    detected = TRUE;
    concludedUrl = "  " + http_report_vuln_url( port:port, url:url1, url_only:TRUE );
  }

  if( "<title>Login to Axis2 :: Administration page</title>" >< buf2 ) {
    detected = TRUE;
    if( concludedUrl )
      concludedUrl += '\n';
    concludedUrl += "  " + http_report_vuln_url( port:port, url:url2, url_only:TRUE );
  }

  if( "<title>Axis 2 - Home</title>" >< buf3 ) {
    detected = TRUE;
    if( concludedUrl )
      concludedUrl += '\n';
    concludedUrl += "  " + http_report_vuln_url( port:port, url:url3, url_only:TRUE );
  }

  if( buf4 =~ "Hello I am Axis2" ||
     ( "getVersionResponse" >< buf4 && "the Axis2 version is" >< buf4 ) ||
     "The system is attempting to access an inactive service: Version" >< buf4 ||
     "The service cannot be found for the endpoint reference (EPR)" >< buf4 ||
     "Service Not found EPR is" >< buf4 ) {
    detected = TRUE;
    if( concludedUrl )
      concludedUrl += '\n';
    concludedUrl += "  " + http_report_vuln_url( port:port, url:url4, url_only:TRUE );
  }

  if( "<title>Axis2 Happiness Page</title>" >< buf5 ) {
    detected = TRUE;
    if( concludedUrl )
      concludedUrl += '\n';
    concludedUrl += "  " + http_report_vuln_url( port:port, url:url5, url_only:TRUE );
  }

  if( "<title>Login to Axis2 :: Administration page</title>" >< buf6 ) {
    detected = TRUE;
    if( concludedUrl )
      concludedUrl += '\n';
    concludedUrl += "  " + http_report_vuln_url( port:port, url:url6, url_only:TRUE );
  }

  if( "<title>Axis2 Happiness Page</title>" >< buf7 ) {
    detected = TRUE;
    if( concludedUrl )
      concludedUrl += '\n';
    concludedUrl += "  " + http_report_vuln_url( port:port, url:url7, url_only:TRUE );
  }

  # nb:
  # - This is slightly different to the others and even has a typo (at least on 0.93)
  # - We're checking both, the typo and the correct spelling just to be sure...
  if( "<title>Login to Axis2:: Administartion page</title>" >< buf8 ||
      "<title>Login to Axis2:: Administration page</title>" >< buf8 ) {
    detected = TRUE;
    if( concludedUrl )
      concludedUrl += '\n';
    concludedUrl += "  " + http_report_vuln_url( port:port, url:url8, url_only:TRUE );
  }

  if( "<title>Axis 2 - Home</title>" >< buf9 ) {
    detected = TRUE;
    if( concludedUrl )
      concludedUrl += '\n';
    concludedUrl += "  " + http_report_vuln_url( port:port, url:url9, url_only:TRUE );
  }

  if( detected ) {

    version = "unknown";

    # <ns:getVersionResponse xmlns:ns="http://axisversion.sample"><ns:return>Hi - the Axis2 version is 1.8.2</ns:return></ns:getVersionResponse>
    # <ns:getVersionResponse xmlns:ns="http://axisversion.sample"><ns:return>Hi - the Axis2 version is 1.7.9</ns:return></ns:getVersionResponse>
    # <ns:getVersionResponse xmlns:ns="http://axisversion.sample"><ns:return>Hi - the Axis2 version is 1.7.2</ns:return></ns:getVersionResponse>
    # <ns:getVersionResponse xmlns:ns="http://axisversion.sample"><ns:return>Hi - the Axis2 version is 1.6.1</ns:return></ns:getVersionResponse>
    # <ns:getVersionResponse xmlns:ns="http://axisversion.sample"><ns:return>Hi - the Axis2 version is 1.5</ns:return></ns:getVersionResponse>
    # <ns:getVersionResponse xmlns:ns="http://axisversion.sample"><ns:return>Hello I am Axis2 version service , My version is 1.4.1</ns:return></ns:getVersionResponse>
    # <ns:getVersionResponse xmlns:ns="http://axisversion.sample"><ns:return>Hello I am Axis2 version service , My version is 1.4</ns:return></ns:getVersionResponse>
    # <my:Version xmlns:my="http://localhost/my">Hello I am Axis2 version service , My version is 0.93 Dec 02, 2005 (08:36:23 LKT)</my:Version>
    vers = eregmatch( string:buf1, pattern:"version is ([0-9.]+)", icase:TRUE );
    if( isnull( vers[1] ) )
      vers = eregmatch( string:buf4, pattern:"version is ([0-9.]+)", icase:TRUE );

    if( ! isnull( vers[1] ) ) {
      version = chomp( vers[1] );
      concluded = vers[0];
    }

    set_kb_item( name:"apache/axis2/detected", value:TRUE );
    set_kb_item( name:"apache/axis2/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:apache:axis2:" );
    if( ! cpe )
      cpe = "cpe:/a:apache:axis2";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Apache Axis2",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:concludedUrl,
                                              concluded:concluded ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
