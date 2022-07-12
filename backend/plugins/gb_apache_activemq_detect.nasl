###############################################################################
# OpenVAS Vulnerability Test
#
# Apache ActiveMQ Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105330");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2015-08-24 12:33:07 +0200 (Mon, 24 Aug 2015)");
  script_name("Apache ActiveMQ Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8161, "Services/activemq_jms", 61616);

  script_tag(name:"summary", value:"The script sends a connection
  request to the server and attempts to detect Apache ActiveMQ.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("dump.inc");

SCRIPT_DESC = "Apache ActiveMQ Detection";
banner_type = "Apache ActiveMQ OS report";

jmsPorts = get_ports_for_service( default_list:make_list( 61616 ), proto:"activemq_jms" );
foreach jmsPort( jmsPorts ) {
  notinkb = FALSE;
  if( ! buf = get_kb_item( "ActiveMQ/JMS/banner/" + jmsPort ) ) {
    if( ! soc = open_sock_tcp( jmsPort ) ) continue;
    buf = recv( socket:soc, length:2048 );
    close( soc );
    if( ! buf ) continue;
    notinkb = TRUE;
    buf = bin2string( ddata:buf );
  }

  # e.g. ActiveMQuTcpNoDelayEnabledSizePrefixDisabledCacheSizeProviderNameActiveMQStackTraceEnabledPlatformDetails
  # PJVM: 1.8.0_141, 25.141-b15, Oracle Corporation, OS: Linux, 4.13.0-1-amd64, amd64CacheEnabledTightEncodingEnabl
  # edMaxFrameSize@MaxInactivityDurationu0 MaxInactivityDurationInitalDelay'ProviderVersion5.14.5
  if( buf =~ "^ActiveMQ" && ( "PlatformDetails" >< buf || "StackTraceEnable" >< buf || "ProviderVersion" >< buf || "TcpNoDelayEnabled" >< buf ) ) {

    if( notinkb ) replace_kb_item( name:"ActiveMQ/JMS/banner/" + jmsPort, value:buf );

    install = jmsPort + "/tcp";
    appVer = "unknown";
    extra = "";

    version = eregmatch( pattern:"ProviderVersion([0-9.]+)", string:buf );
    if( version[1] ) appVer = version[1];

    jvm = eregmatch( pattern:"JVM: ([0-9._]+)", string:buf );
    if( jvm[1] ) extra = "Java JVM version " + jvm[1] + " in use";

    os = eregmatch( pattern:"OS: ([a-zA-Z]+), (([a-zA-Z0-9.\-]+),)?", string:buf );
    if( os[1] ) {
      if( "windows" >< tolower( os[1] ) ) {
        register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, banner:os[0], port:jmsPort, desc:SCRIPT_DESC, runs_key:"windows" );
      } else if( "linux" >< tolower( os[1] ) ) {
        if( os[3] ) {
          register_and_report_os( os:"Linux", version:os[3], cpe:"cpe:/o:linux:kernel", banner_type:banner_type, banner:os[0], port:jmsPort, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, banner:os[0], port:jmsPort, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
      } else {
        # nb: Setting the runs_key to unixoide makes sure that we still schedule NVTs using Host/runs_unixoide as a fallback
        register_and_report_os( os:os[1], banner_type:banner_type, banner:os[0], port:jmsPort, desc:SCRIPT_DESC, runs_key:"unixoide" );
        register_unknown_os_banner( banner:os[0], banner_type_name:banner_type, banner_type_short:"activemq_os_banner", port:jmsPort );
      }
    }

    cpe = build_cpe( value:appVer, exp:"^([0-9.]+)", base:"cpe:/a:apache:activemq:" );
    if( ! cpe )
      cpe = "cpe:/a:apache:activemq";

    set_kb_item( name:"ActiveMQ/installed", value:TRUE );
    set_kb_item( name:"ActiveMQ/JMS/detected", value:TRUE );

    register_product( cpe:cpe, location:install, port:jmsPort, service:"jms" );

    log_message( data:build_detection_report( app:"Apache ActiveMQ",
                                              install:install,
                                              version:appVer,
                                              concluded:version[0],
                                              extra:extra,
                                              cpe:cpe ),
                                              port:jmsPort );
  }
}

if( http_is_cgi_scan_disabled() ) exit( 0 );

port = get_http_port( default:8161 );

url = "/admin/index.jsp";
buf = http_get_cache( item:url, port:port );
if( ! buf ) exit( 0 );
host = http_host_name( dont_add_port:TRUE );

if( egrep( pattern:"(Apache )?ActiveMQ( Console)?</title>", string:buf, icase:TRUE ) ||
    'WWW-Authenticate: basic realm="ActiveMQRealm"' >< buf ) {

  install = "/";
  appVer = "unknown";
  conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

  # nb: Basic auth check for default_http_auth_credentials.nasl
  if( 'WWW-Authenticate: basic realm="ActiveMQRealm"' >< buf ) {
    set_kb_item( name:"www/content/auth_required", value:TRUE );
    set_kb_item( name:"www/" + host + "/" + port + "/content/auth_required", value:url );
    set_kb_item( name:"www/" + host + "/" + port + "/ActiveMQ/Web/auth_required", value:url );
    set_kb_item( name:"ActiveMQ/Web/auth_required", value:TRUE );
    set_kb_item( name:"ActiveMQ/Web/auth_or_unprotected", value:TRUE );
  } else if( egrep( pattern:"(Apache )?ActiveMQ( Console)?</title>", string:buf, icase:TRUE ) ) {
    set_kb_item( name:"www/" + host + "/" + port + "/ActiveMQ/Web/unprotected", value:url );
    set_kb_item( name:"ActiveMQ/Web/unprotected", value:TRUE );
    set_kb_item( name:"ActiveMQ/Web/auth_or_unprotected", value:TRUE );
  }

  # nb: Getting version from admin page, in some cases admin page is accessible where we can get the version
  version = eregmatch( pattern:'Version.*<td><b>([0-9.]+).*<td>ID', string:buf );
  if( version[1] ) appVer = version[1];

  cpe = build_cpe( value:appVer, exp:"^([0-9.]+)", base:"cpe:/a:apache:activemq:" );
  if( ! cpe )
    cpe = "cpe:/a:apache:activemq";

  set_kb_item( name:"ActiveMQ/installed", value:TRUE );
  set_kb_item( name:"ActiveMQ/Web/detected", value:TRUE );

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Apache ActiveMQ",
                                            install:install,
                                            version:appVer,
                                            concluded:appVer,
                                            concludedUrl:conclUrl,
                                            cpe:cpe ),
                                            port:port );
}

exit( 0 );
