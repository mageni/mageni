###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_sphinxsearch_detect.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# Sphinx search server Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111034");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10915 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-08-31 18:00:00 +0200 (Mon, 31 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sphinx search server Detection");

  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/sphinxql", 9306, "Services/sphinxapi", 9312);

  script_tag(name:"summary", value:"The script checks the presence of a Sphinx search server
  and sets the version in the kb.");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("dump.inc");
include("misc_func.inc");

ports = get_kb_list( "Services/sphinxql" );
if( ! ports) ports = make_list( 9306 );

foreach port ( ports ) {

  if( get_port_state( port ) ) {

    soc = open_sock_tcp( port );
    if( soc ) {

      send( socket: soc, data: "TEST\r\n" );

      buf = recv( socket:soc, length:64 );
      close( soc );

      if( version = eregmatch( string:bin2string( ddata:buf, noprint_replacement:' ' ), pattern: "([0-9.]+)-id([0-9]+)-release \(([0-9a-z\-]+)\)" ) ) {

        register_service(port:port, proto:"sphinxql");
        set_kb_item( name:"sphinxsearch/" + port + "/version", value: version[1] );
        set_kb_item( name:"sphinxsearch/" + port + "/installed", value: TRUE );

        ## CPE is currently not registered
        cpe = build_cpe( value: version[1], exp:"^([0-9.]+)",base:"cpe:/a:sphinxsearch:sphinxsearch:" );
        if( isnull( cpe ) )
          cpe = 'cpe:/a:sphinxsearch:sphinxsearch';

        register_product( cpe:cpe, location:port + '/tcp', port:port );

        log_message( data: build_detection_report( app:"Sphinx search server",
                                                       version:version[1],
                                                       install:port + '/tcp',
                                                       cpe:cpe,
                                                       concluded:version[0]),
                                                       port:port);
      }
    }
  }
}

port = get_kb_item( "Services/sphinxapi" );
if ( ! port ) port = 9312;

if( get_port_state( port ) ) {

  soc = open_sock_tcp( port );
  if( soc ) {

    send( socket: soc, data: "TEST\r\n\r\n" );

    buf = recv( socket:soc, length:64 );
    close( soc );

    if( banner = egrep( string: bin2string( ddata:buf, noprint_replacement:' ' ), pattern: "invalid command \(code=([0-9]+), len=([0-9]+)\)" ) ) {

      version = "unknown";

      register_service(port:port, proto:"sphinxapi");
      set_kb_item( name:"sphinxsearch/" + port + "/version", value: version );
      set_kb_item( name:"sphinxsearch/" + port + "/installed", value: TRUE );

      ## CPE is currently not registered
      cpe = 'cpe:/a:sphinxsearch:sphinxsearch';

      register_product( cpe:cpe, location:port + '/tcp', port:port );

      log_message( data: build_detection_report( app:"Sphinx search server",
                                                     version:version,
                                                     install:port + '/tcp',
                                                     cpe:cpe,
                                                     concluded:banner),
                                                     port:port);
    }
  }
}

exit(0);
