###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ecessa_shieldlink_snmp_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Ecessa ShieldLink Detection (SNMP)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113223");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-07-06 10:41:45 +0200 (Fri, 06 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Ecessa ShieldLink Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"Checks if the target is an Ecessa ShieldLink
  or PowerLink device, and, if so, retrieves the version using SNMP.");

  script_xref(name:"URL", value:"https://www.ecessa.com/powerlink/");
  script_xref(name:"URL", value:"https://www.ecessa.com/powerlink/product_comp_shieldlink/");

  exit(0);
}

include( "host_details.inc" );
include( "snmp_func.inc" );

port = get_snmp_port( default: 161 );
sysdesc = get_snmp_sysdesc( port: port );
if( ! sysdesc ) exit( 0 );

if( sysdesc =~ '^ShieldLink' ) {
  kb_base = 'ecessa_shieldlink';
}
else if ( sysdesc =~ '^PowerLink' ) {
  kb_base = 'ecessa_powerlink';
}
else {
  exit( 0 );
}

set_kb_item( name: "ecessa_link/detected", value: TRUE );
set_kb_item( name: kb_base + "/detected", value: TRUE );
set_kb_item( name: kb_base + "/snmp/port", value: port );
set_kb_item( name: kb_base + "/snmp/concluded", value: sysdesc );

version = "unknown";

vers = eregmatch( string: sysdesc, pattern: 'Link ([0-9.]+) Ecessa' );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
}

set_kb_item( name: kb_base + "/snmp/version", value: version );

exit( 0 );
