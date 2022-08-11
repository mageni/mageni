###############################################################################
# OpenVAS Vulnerability Test
# $Id: hp_data_protector_installed.nasl 10899 2018-08-10 13:49:35Z cfischer $
#
# HP/HPE (OpenView Storage) Data Protector Detection
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.19601");
  script_version("$Revision: 10899 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:49:35 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("HP/HPE (OpenView Storage) Data Protector Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2005 Josh Zlatin-Amishav");
  script_require_ports("Services/hp_dataprotector", 5555);
  script_dependencies("find_service2.nasl");

  script_tag(name:"summary", value:"Detection of HP/HPE (OpenView Storage) Data Protector.

  The script sends a connection request to the HP/HPE (OpenView Storage) Data Protector
  and attempts to extract the version number from the reply.");

  script_xref(name:"URL", value:"https://saas.hpe.com/en-us/software/data-protector");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_kb_item( "Services/hp_dataprotector" );
if( ! port ) port = 5555;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port) ;
if( ! soc ) exit( 0 );

# HP Data Protector A.06.10: INET, internal build 611, built on 2008
# HPE Data Protector A.09.09: INET, internal build 114, built on Tuesday, March 28, 2017, 5:02 PM
# HP OpenView Storage Data Protector A.06.00: INET, internal build 331
# HP OpenView Storage Data Protector A.05.50: INET, internal build 330
versionpat = 'Data Protector ([^:]+)';
buildpat   = 'internal build ([^,]+)';

# Data Protector can take some time to return its header
response = recv( socket:soc, length:4096, timeout:20 );
close( soc );

if( "HP OpenView Storage Data Protector" >< response ||
    "HP Data Protector" >< response ||
    "HPE Data Protector" >< response ) {

  versionmatches = egrep( pattern:versionpat, string:response );
  if( versionmatches ) {
    foreach versionmatch( split( versionmatches ) ) {
      versions = eregmatch( pattern:versionpat, string:versionmatch );
    }
  }

  buildmatches = egrep( pattern:buildpat, string:response );
  if( buildmatches ) {
    foreach buildmatch( split( buildmatches ) ) {
      builds = eregmatch( pattern:buildpat, string:buildmatch );
    }
  }

  if( versions[1] == "" && builds[1] == "") {
    versions[1] = "unknown";
    builds[1]   = "unknown";
  }

  # In case the service wasn't identified before
  register_service( port:port, proto:"hp_dataprotector" );

  set_kb_item( name:"hp_data_protector/installed", value:TRUE );
  set_kb_item( name:"hp_data_protector/" + port + "/version", value:versions[1] );
  set_kb_item( name:"hp_data_protector/" + port + "/build", value:builds[1] );

  cpe = build_cpe( value:versions[1], exp:"^[a-zA-Z]\.([0-9.]+)", base:"cpe:/a:hp:data_protector:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:hp:data_protector";

  install = port + "/tcp";
  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"HP/HPE (OpenView Storage) Data Protector",
                                            version:versions[1] + ' build ' + builds[1],
                                            install:install,
                                            cpe:cpe,
                                            concluded:response ),
                                            port:port );
}

exit( 0 );