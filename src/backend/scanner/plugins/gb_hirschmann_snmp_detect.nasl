###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hirschmann_snmp_detect.nasl 8449 2018-01-17 17:04:52Z cfischer $
#
# Hirschmann Devices Detection (SNMP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108313");
  script_version("$Revision: 8449 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 18:04:52 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-12-11 11:03:31 +0100 (Mon, 11 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Hirschmann Devices Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Hirschmann Devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port( default:161 );
sysdesc = get_snmp_sysdesc( port:port );
if( ! sysdesc || sysdesc !~ "^Hirschmann" ) exit( 0 );

set_kb_item( name:"hirschmann_device/detected", value:TRUE );
set_kb_item( name:"hirschmann_device/snmp/detected", value:TRUE );
set_kb_item( name:"hirschmann_device/snmp/port", value:port );

fw_version    = "unknown";
product_name  = "unknown";
platform_name = "unknown";

# Hirschmann MACH
# Hirschmann BAT-R 9.12.5750 / 20.10.2017 942070999000000110
# Hirschmann EAGLE Security Device
# Hirschmann Modular Industrial Communication Equipment
# Hirschmann Railswitch
prod_name = eregmatch( pattern:'^Hirschmann ([^\n0-9]+)', string:sysdesc );
if( prod_name[1] ) product_name = chomp( prod_name[1] );

# https://github.com/librenms/librenms/blob/master/mibs/hirschmann/hmpriv.mib
# http://www.circitor.fr/Mibs/Html/H/HMPRIV-MGMT-SNMP-MIB.php
oid = snmp_get( port:port, oid:"1.3.6.1.4.1.248.14.1.1.2.0" ); #hmSysVersion, hmPNIOSoftwareRelease seems to be not available on the tested devices

# SW: 5.07 CH: 1.00 BP: 000
# SW: L2P-09.0.04 CH: 1.10 BP: 000
sw_banner = eregmatch( pattern:"^SW: (.*) CH: ", string:oid );

if( sw_banner ) {

  set_kb_item( name:"hirschmann_device/snmp/" + port + "/concluded", value:oid );
  set_kb_item( name:"hirschmann_device/snmp/" + port + "/concludedOID", value:"1.3.6.1.4.1.248.14.1.1.2.0" );

  vers_nd_model = eregmatch( pattern:"([0-9a-zA-Z]+)-([0-9a-zA-Z]+-)?([0-9.]+)", string:sw_banner[1] );

  if( vers_nd_model ) {

    fw_version = vers_nd_model[3];

    if( vers_nd_model[2] ) {
      platform_name  = vers_nd_model[1] + "-";
      platform_name += ereg_replace( pattern:"-$", string:vers_nd_model[2], replace:"" );
    } else {
      platform_name = vers_nd_model[1];
    }
  } else {
    vers = eregmatch( pattern:"([0-9.]+)", string:sw_banner[1] );
    if( vers ) fw_version = vers[1];
  }
} else {
  set_kb_item( name:"hirschmann_device/snmp/" + port + "/concluded", value:sysdesc );
}

set_kb_item( name:"hirschmann_device/snmp/" + port + "/fw_version", value:fw_version );
set_kb_item( name:"hirschmann_device/snmp/" + port + "/product_name", value:product_name );
set_kb_item( name:"hirschmann_device/snmp/" + port + "/platform_name", value:platform_name );

exit( 0 );
