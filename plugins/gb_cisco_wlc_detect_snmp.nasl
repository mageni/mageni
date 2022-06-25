###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wlc_detect_snmp.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Wireless LAN Controller Detection (SNMP)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105382");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-09-22 14:49:34 +0200 (Tue, 22 Sep 2015)");
  script_name("Cisco Wireless LAN Controller Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Cisco Wireless LAN Controller");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

if( "Cisco Controller" >!< sysdesc ) exit( 0 );

set_kb_item( name:"cisco_wlc/detected", value:TRUE );

if( defined_func( "snmpv2c_get" ) )
{
  community = snmp_get_community( port:port );
  if( ! community) community = "public";

  version = snmpv2c_get( port:port, protocol:'udp', community:community, oid:'1.3.6.1.2.1.47.1.1.1.1.10.1' );
  if( version[0] == 0 )
  {
    vers = str_replace( string:version[1], find:'"', replace:"" );
    set_kb_item( name:"cisco_wlc/version/snmp", value:vers );
  }

  model = snmpv2c_get( port:port, protocol:'udp', community:community, oid:'1.3.6.1.2.1.47.1.1.1.1.13.1');
  if( model[0] == 0 )
  {
    mod = str_replace( string:model[1], find:'"', replace:"" );
    set_kb_item( name:"cisco_wlc/model/snmp", value:mod );
  }
}

exit(0);

