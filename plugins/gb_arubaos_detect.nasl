###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arubaos_detect.nasl 8143 2017-12-15 13:11:11Z cfischer $
#
# ArubaOS Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105244");
  script_version("$Revision: 8143 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:11:11 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-04-07 13:29:41 +0200 (Tue, 07 Apr 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ArubaOS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of ArubaOS");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port( default:161 );
sysdesc = get_snmp_sysdesc( port:port );
if( ! sysdesc ) exit( 0 );

# ArubaOS (MODEL: Aruba3400), Version 6.3.1.1 (40563)
# ArubaOS (MODEL: Aruba200-US), Version 5.0.4.16 (43995)
# ArubaOS Version 6.1.2.3-2.1.0.0
if( "ArubaOS" >!< sysdesc ) exit( 0 );

set_kb_item( name:"ArubaOS/installed", value:TRUE );
cpe = "cpe:/o:arubanetworks:arubaos";

vers    = "unknown";
build   = FALSE;
model   = FALSE;
install = port + "/udp";

version = eregmatch( pattern:"Version ([^ ]+)", string:sysdesc );

if( ! isnull( version[1] ) ) {
  vers = chomp( version[1] );
  set_kb_item( name:"ArubaOS/version", value:vers );
  rep_vers = vers;
  cpe += ':' + vers;
}

b = eregmatch( pattern:"Version [^ ]+ \(([0-9]+)\)", string:sysdesc );
if( ! isnull( b[1] ) ) {
  build = b[1];
  set_kb_item( name:"ArubaOS/build", value:build );
  rep_vers += ' (' + build + ')';
  extra += "Build: " + build;
}

mod = eregmatch( pattern:"\(MODEL: ([^)]+)\)", string:sysdesc );
if( ! isnull( mod[1] ) ) {
  model = mod[1];
  set_kb_item( name:"ArubaOS/model", value:model );
  if( extra ) extra += '\n';
  extra += "Model: " + model;
}

register_product( cpe:cpe, port:port, proto:"udp", location:install, service:"snmp" );
register_and_report_os( os:"ArubaOS", cpe:cpe, banner_type:"SNMP sysdesc", banner:sysdesc, port:port, proto:"udp", desc:"ArubaOS Detection", runs_key:"unixoide" );


log_message( data:build_detection_report( app:"ArubaOS",
                                          version:rep_vers,
                                          install:install,
                                          cpe:cpe,
                                          extra:extra,
                                          concluded:sysdesc ),
                                          port:port,
                                          proto:"udp" );
exit( 0 );
