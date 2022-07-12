###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_greenbone_os_detect_snmp.nasl 7902 2017-11-24 11:02:42Z cfischer $
#
# Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (SNMP)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112138");
  script_version("$Revision: 7902 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-24 12:02:42 +0100 (Fri, 24 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-23 11:04:05 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of the Greenbone Security Manager (GSM) / Greenbone OS (GOS).");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("snmp_func.inc");
include("misc_func.inc");

port = get_snmp_port( default:161 );

if( ! sysdesc = get_snmp_sysdesc( port:port ) ) exit ( 0 );

if ( "Greenbone Security Manager" >< sysdesc ) {

  # This OID should contain both the GSM type and GOS version.
  oid = snmp_get( port:port, oid:"1.3.6.1.2.1.1.5.0" );

  set_kb_item( name:"greenbone/gos/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/snmp/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/snmp/port", value:port );

  type_nd_vers = eregmatch( pattern:"^([0-9]+|ONE|25V)-([0-9\-]+)", string:oid );

  if( !isnull( type_nd_vers[1] ) ) {
    gsm_type = type_nd_vers[1];
    set_kb_item( name:"greenbone/gsm/snmp/" + port + "/type", value:gsm_type );
  }
  if( !isnull( type_nd_vers[2] ) ) {
    gos_ver = str_replace( string:type_nd_vers[2], find:"-", replace:".");
    set_kb_item( name:"greenbone/gos/snmp/" + port + "/version", value:gos_ver );
    set_kb_item( name:"greenbone/gos/snmp/" + port + "/concluded", value:oid );
    set_kb_item( name:"greenbone/gos/snmp/" + port + "/concludedOID", value:"1.3.6.1.2.1.1.5.0" );
  } else {
    set_kb_item( name:"greenbone/gos/snmp/" + port + "/concluded", value:sysdesc );
  }
}

exit( 0 );
