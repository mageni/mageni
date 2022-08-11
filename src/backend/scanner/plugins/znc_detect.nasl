###############################################################################
# OpenVAS Vulnerability Test
#
# ZNC Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100243");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ZNC Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "find_service2.nasl", "http_version.nasl");
  script_require_ports("Services/irc", "Services/www", 6667);

  script_xref(name:"URL", value:"http://en.znc.in/wiki/ZNC");

  script_tag(name:"summary", value:"This host is running ZNC, an IRC Bouncer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

ports = get_ports_for_service( default_list:make_list( 6667 ), proto:"irc" );
foreach port( ports ) {

  soc = open_sock_tcp( port );
  if( ! soc ) continue;

  req = string( "USER\r\n" );
  send( socket:soc, data:req );

  buf = recv_line( socket:soc, length:64 );
  close( soc );

  if( egrep( pattern:"irc\.znc\.in NOTICE AUTH", string:buf, icase:TRUE ) ||
      ( "irc.znc.in" >< buf && "Password required" >< buf ) ) {

    vers    = "unknown";
    install = port + "/tcp";

    set_kb_item( name:"znc/installed", value:TRUE );
    set_kb_item( name:"znc/irc/detected", value:TRUE );

    cpe = "cpe:/a:znc:znc";
    register_product( cpe:cpe, location:install, port:port, service:"irc" );

    log_message( data:build_detection_report( app:"ZNC",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:buf ),
                                              port:port );
  }
}

if( http_is_cgi_scan_disabled() ) exit( 0 );

httpPort = get_http_port( default:6667 );
banner = get_http_banner( port:httpPort );
buf = http_get_cache( item:"/", port:httpPort );

# only way to get version is from webadmin-module (if enabled).
if( ( banner && "Server: ZNC" >< banner ) || ( buf && "ZNC - Web Frontend" >< buf ) ) {

  vers    = "unknown";
  install = httpPort + "/tcp";

  version = eregmatch( string:banner, pattern:"Server: ZNC (- )?([0-9.]+)", icase:TRUE );

  if( ! isnull( version[2] ) ) {
    vers = version[2];
  } else {
    version = eregmatch( string:buf, pattern:"ZNC (- )?([0-9.]+)", icase:TRUE );
    if ( ! isnull( version[2] ) )
      vers = version[2];
  }

  if( vers != "unknown" )
    set_kb_item( name:"znc/version", value:vers );

  set_kb_item( name:"znc/installed", value:TRUE );
  set_kb_item( name:"znc/web/detected", value:TRUE );

  cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:znc:znc:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:znc:znc";

  register_product( cpe:cpe, location:install, port:httpPort, service:"www" );

  log_message( data:build_detection_report( app:"ZNC",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version[0] ),
                                            port:httpPort );
}

exit( 0 );
