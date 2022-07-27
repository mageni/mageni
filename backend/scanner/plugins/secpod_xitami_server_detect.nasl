###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xitami_server_detect.nasl 13507 2019-02-06 15:12:15Z cfischer $
#
# Xitami Server Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900547");
  script_version("$Revision: 13507 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 16:12:15 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-05-06 08:04:28 +0200 (Wed, 06 May 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Xitami Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("httpver.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/www", 80, "Services/ftp", 21, 990);

  script_tag(name:"summary", value:"Detection of Xitami Server.

  This script tries to detect an installed Xitami Server and its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ftp_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

ports = ftp_get_ports();
foreach port( ports ) {

  banner = get_ftp_banner( port:port );
  if( ! banner || ( "Welcome to this Xitami FTP server" >!< banner && "220 Xitami FTP " >!< banner ) )
    continue;

  set_kb_item( name:"xitami/detected", value:TRUE );
  set_kb_item( name:"xitami/ftp/detected", value:TRUE );
  version = "unknown";
  install = port + "/tcp";

  # 220- Welcome to this Xitami FTP server, running version 2.5b5 of Xitami.
  # 220 Xitami FTP 2.5c2 (c) 1991-2002 iMatix <http://www.imatix.com>
  vers = eregmatch( pattern:"(220 Xitami FTP |Xitami FTP server, running version )([0-9a-z.]+)", string:banner );
  if( vers[2] ) {
    version = vers[2];
    set_kb_item( name:"xitami/version", value:version );
    set_kb_item( name:"xitami/ftp/version", value:version );
    cpe = build_cpe( value:version, exp:"^([0-9a-z.]+)", base:"cpe:/a:imatix:xitami:" );
  }

  if( ! cpe )
    cpe = "cpe:/a:imatix:xitami";

  register_product( cpe:cpe, location:install, port:port, service:"ftp" );
  log_message( data:build_detection_report( app:"Xitami Server",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            port:port );
}

if( http_is_cgi_scan_disabled() )
  exit( 0 );

port   = get_http_port( default:80 );
banner = get_http_banner( port:port );
res    = http_get_cache( port:port, item:"/" );

# <TITLE>Welcome To Xitami v2.5b6</TITLE></HEAD>
# <H1>Welcome To Xitami v2.5b6</H1>
if( ! res || ( "erver: Xitami" >!< banner && ">Welcome To Xitami " >!< res ) )
  exit( 0 );

set_kb_item( name:"xitami/detected", value:TRUE );
set_kb_item( name:"xitami/http/detected", value:TRUE );
version = "unknown";
cpe = ""; # Overwrite a possible existing cpe from the FTP detection
install = port + "/tcp";

vers = eregmatch( pattern:"Welcome To Xitami v([0-9]\.[0-9a-z.]+)", string:res );
if( vers[1] ) {
  version  = vers[1];
  conclUrl = report_vuln_url( port:port, url:"/", url_only:TRUE );
}

if( version == "unknown" ) {
  vers = eregmatch( pattern:"Xitami(\/([0-9]\.[0-9.]+)([a-z][0-9]?)?)", string:banner );
  if( vers[1] ) {
    version  = vers[1];
    conclUrl = report_vuln_url( port:port, url:"/", url_only:TRUE );
  }
}

if( version == "unknown" ) {
  url = "/xitami/index.htm";
  req = http_get( port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req );
  # <FONT SIZE=4><B>Xitami</B><BR><FONT SIZE=2>Version 2.5b6
  vers = eregmatch( pattern:"Xitami</B>.*Version ([0-9]\.[0-9a-z.]+)", string:res );
  if( vers[1] ) {
    version  = vers[1];
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
  }
}

if( version != "unknown" ) {
  set_kb_item( name:"xitami/version", value:version );
  set_kb_item( name:"xitami/http/version", value:version );
  cpe = build_cpe( value:version, exp:"^([0-9a-z.]+)", base:"cpe:/a:imatix:xitami:" );
}

if( ! cpe )
  cpe = "cpe:/a:imatix:xitami";

register_product( cpe:cpe, location:install, port:port, service:"www" );

log_message( data:build_detection_report( app:"Xitami Server",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concludedUrl:conclUrl,
                                          concluded:vers[0] ),
                                          port:port );
exit( 0 );