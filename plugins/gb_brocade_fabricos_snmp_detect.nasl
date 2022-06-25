###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_brocade_fabricos_snmp_detect.nasl 8826 2018-02-15 11:12:22Z cfischer $
#
# Brocade Fabric OS Detection (SNMP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108337");
  script_version("$Revision: 8826 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-15 12:12:22 +0100 (Thu, 15 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-15 11:09:51 +0100 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Brocade Fabric OS Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"The script sends a SNMP request to the device and attempts
  to detect the presence of devices running Fabric OS and to extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("snmp_func.inc");
include("misc_func.inc");

port = get_snmp_port( default:161 );

# nb: The sysdesc only contains the device name running Fabric OS so don't rely on this
# e.g. Fibre Channel Switch or Connectrix ED-DCX-4S-B
if( ! sysdesc = get_snmp_sysdesc( port:port ) ) exit ( 0 );

# swFirmwareVersion
fw_oid = "1.3.6.1.4.1.1588.2.1.1.1.1.6.0";
fw_res = snmp_get( port:port, oid:fw_oid );
# nb: There is no other OID available which would allow to make a more precise detection
# e.g. v3.2.1 or v7.2.1d
if( fw_res =~ "^v([0-9a-z.]+)$" ) {

  version = "unknown";
  set_kb_item( name:"brocade_fabricos/detected", value:TRUE );
  set_kb_item( name:"brocade_fabricos/snmp/detected", value:TRUE );
  set_kb_item( name:"brocade_fabricos/snmp/port", value:port );

  vers = eregmatch( pattern:"^v([0-9a-z.]+)", string:fw_res );
  if( vers[1] ) {
    version = vers[1];
    set_kb_item( name:"brocade_fabricos/snmp/" + port + "/version", value:version );
    set_kb_item( name:"brocade_fabricos/snmp/" + port + "/concluded", value:fw_res );
    set_kb_item( name:"brocade_fabricos/snmp/" + port + "/concludedOID", value:fw_oid );
  }
}

exit( 0 );
