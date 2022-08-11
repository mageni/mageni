###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openvas_manager_detect.nasl 13874 2019-02-26 11:51:40Z cfischer $
#
# OpenVAS / Greenbone Vulnerability Manager Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103825");
  script_version("$Revision: 13874 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 12:51:40 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-11-08 12:24:10 +0100 (Fri, 08 Nov 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OpenVAS / Greenbone Vulnerability Manager Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service3.nasl");
  script_require_ports("Services/omp_gmp", 9390);

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  determine if it is a OpenVAS Manager (openvasmd) or Greebone Vulnerability Manager (gmvd).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("version_func.inc");

port = get_port_for_service( default:9390, proto:"omp_gmp" );
soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

vt_strings = get_vt_strings();
req = "<" + vt_strings["lowercase"] + "/>";
send( socket:soc, data:req + '\r\n' );
res = recv( socket:soc, length:256 );
close( soc );

# nb: GMP and OMP services are both still answering with an omp_response only
# so we only can differ between the protocol based on its version later.
if( "omp_response" >< res && "GET_VERSION" >< res ) {

  set_kb_item( name:"openvasmd_gvmd/detected", value:TRUE );
  set_kb_item( name:"openvas_gvm/framework_component/detected", value:TRUE );

  manager_version = "unknown";
  prot_version = "unknown";
  install = port + "/tcp";
  proto = "omp_gmp";

  # nb: Defaults if we're not able to catch the version later.
  app_name = "OpenVAS / Greenbone Vulnerability Manager";
  base_cpe = "cpe:/a:greenbone:greenbone_vulnerability_manager";
  concluded = "OMP/GMP protocol probe '" + req + "', response: " + res;

  # nb: We need to re-open the socket as the Manager isn't accepting further commands after the initial request above.
  soc = open_sock_tcp( port );
  if( soc ) {

    req = "<GET_VERSION/>";
    send( socket:soc, data:req + '\r\n' );
    res = recv( socket:soc, length:256 );
    close( soc );

    ver = eregmatch( pattern:"<version>([0-9.]+)</version>", string:res );
    if( ver[1] ) {

      prot_version = ver[1];

      if( version_is_less( version:prot_version, test_version:"8.0" ) ) {
        app_name = "OpenVAS Manager";
        base_cpe = "cpe:/a:openvas:openvas_manager";
        concluded = "OMP protocol version request '" + req + "', response: " + ver[0];
      } else {
        app_name = "Greenbone Vulnerability Manager";
        base_cpe = "cpe:/a:greenbone:greenbone_vulnerability_manager";
        concluded = "GMP protocol version request '" + req + "', response: " + ver[0];
      }

      # We can fingerprint the major OpenVAS / Greenbone Vulnerability Manager version from the supported OMP/GMP
      # protocol version. The OMP/GMP protocol version is currently matching the OpenVAS / Greenbone Vulnerability Manager
      # protocol but that could change.
      # https://docs.greenbone.net/#api_documentation
      if( prot_version == "8.0" ) {
        manager_version = "8.0";
      } else if( prot_version == "7.0" ) {
        manager_version = "7.0";
      } else if( prot_version == "6.0" ) {
        manager_version = "6.0";
      } else if( prot_version == "5.0" ) {
        manager_version = "5.0";
      } else if( prot_version == "4.0" ) {
        manager_version = "4.0";
      } else if( prot_version == "3.0" ) {
        manager_version = "3.0";
      } else if( prot_version == "2.0" ) {
        manager_version = "2.0";
      } else if( prot_version == "1.0" ) {
        manager_version = "1.0";
      }
    }
  }

  cpe = build_cpe( value:manager_version, exp:"^([0-9.]+)", base:base_cpe + ":" );
  if( ! cpe )
    cpe = base_cpe;

  register_service( port:port, proto:proto );
  register_product( cpe:cpe, location:install, port:port, service:proto );

  log_message( data:build_detection_report( app:app_name,
                                            version:manager_version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded ),
                                            port:port );
}

exit( 0 );
