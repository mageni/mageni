###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_prosafe_snmp_detect.nasl 8078 2017-12-11 14:28:55Z cfischer $
#
# NETGEAR ProSAFE Devices Detection (SNMP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108163");
  script_version("$Revision: 8078 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-11 15:28:55 +0100 (Mon, 11 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-05-18 10:24:16 +0200 (Thu, 18 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NETGEAR ProSAFE Devices Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of NETGEAR ProSAFE devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port( default:161 );
sysdesc = get_snmp_sysdesc( port:port );
if( ! sysdesc || ( "ProSafe" >!< sysdesc && "ProSAFE" >!< sysdesc ) ) exit( 0 );

set_kb_item( name:"netgear/prosafe/detected", value:TRUE );
set_kb_item( name:"netgear/prosafe/snmp/detected", value:TRUE );
set_kb_item( name:"netgear/prosafe/snmp/port", value:port );

model      = "unknown";
fw_version = "unknown";
fw_build   = "unknown";

# Netgear ProSafe VPN Firewall FVS318v3
# ProSafe 802.11b/g Wireless Access Point -WG102 V5.2.8
# M4300-24X24F ProSAFE 24-port 10GBASE-T and 24-port 10G SFP+, 12.0.2.17, 1.0.0.8
# GS748Tv5 ProSafe 48-port Gigabit Ethernet Smart Switch, 6.3.1.11, B1.0.0.4
# M4100-26G ProSafe 24-port Gigabit L2+ Intelligent Edge Managed Switch, 10.0.1.16, B1.0.0.9
# GSM7224V2 - ProSafe 24G
if( "Netgear ProSafe VPN Firewall" >< sysdesc ) {
  pattern = "^Netgear ProSafe VPN Firewall ([0-9a-zA-Z\-]+)";
} else if ("ProSafe 802.11b/g Wireless Access Point" >< sysdesc ) {
  pattern = "^ProSafe 802.11b/g Wireless Access Point -([0-9a-zA-Z\-]+) V([0-9.]+)";
} else {
  pattern = "^([0-9a-zA-Z\-]+) [- ]+?ProSafe[^,]+(, ([0-9.]+), B?([0-9.]+))?";
  offset = 1;
}

model_fw_nd_build = eregmatch( pattern:pattern, string:sysdesc, icase:TRUE );
if( ! isnull( model_fw_nd_build[1] ) ) model = model_fw_nd_build[1];
if( ! isnull( model_fw_nd_build[2] ) ) fw_version = model_fw_nd_build[2+offset];
if( ! isnull( model_fw_nd_build[3] ) ) fw_build = model_fw_nd_build[3+offset];

set_kb_item( name:"netgear/prosafe/snmp/" + port + "/model", value:model );
set_kb_item( name:"netgear/prosafe/snmp/" + port + "/fw_version", value:fw_version );
set_kb_item( name:"netgear/prosafe/snmp/" + port + "/fw_build", value:fw_build );
set_kb_item( name:"netgear/prosafe/snmp/" + port + "/concluded", value:sysdesc );

exit( 0 );
