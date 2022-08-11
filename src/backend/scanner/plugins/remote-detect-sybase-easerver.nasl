# OpenVAS Vulnerability Test
# $Id: remote-detect-sybase-easerver.nasl 12413 2018-11-19 11:11:31Z cfischer $
# Description: This script ensure that the Sybase EAServer is installed and running
#
# remote-detect-sybase-easerver.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80006");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12413 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sybase Enterprise Application Server service detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host is running the Sybase Enterprise Application Server.
  Sybase EAServer is the open application server from Sybase Inc
  an enterprise software and services company exclusively focused on managing and mobilizing information.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:80 );

buf = http_get_cache( item:"/", port:port );

version = 'unknown';
concluded = ''; # nb: To make openvas-nasl-lint happy...

if( ( "<TITLE>Sybase EAServer<" >< buf || egrep( pattern:"Sybase EAServer", string:buf ) ) ) {

  identified = 1;
  ver = eregmatch( pattern:'EAServer ([0-9.]+)', string:buf );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
    concluded += '\n- ' + ver[0];
  }
}

req = http_get( item:"/WebConsole/Login.jsp", port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( detectedConsole = eregmatch( string: buf, pattern: "Sybase Management Console Login" ) ) {

  identified = 1;
  concluded += '\n- /WebConsole/Login.jsp';
  set_kb_item( name:"SybaseJSPConsole/installed", value:TRUE );
}

banner = get_http_banner( port:port );

if( detectedBanner = eregmatch( string: banner, pattern: "Server: Jaguar Server Version([ 0-9.]+)", icase: TRUE ) ) {

  identified = 1;
  concluded += '\n- ' + detectedBanner[0];
}

if( identified ) {

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:sybase:easerver:");
  if( isnull( cpe ) )
    cpe = 'cpe:/a:sybase:easerver';

  set_kb_item( name:"www/" + port + "/SybaseEAServer", value:version );
  set_kb_item( name:"SybaseEAServer/installed", value:TRUE );

  register_product( cpe:cpe, location:port + "/tcp", port:port );

  log_message( data: build_detection_report( app:"Sybase Enterprise Application Server",
                                             version:version,
                                             install:port + "/tcp",
                                             cpe:cpe,
                                             concluded: concluded),
               port:port );
}

exit( 0 );