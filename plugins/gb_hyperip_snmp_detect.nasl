###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hyperip_snmp_detect.nasl 8951 2018-02-26 11:47:22Z cfischer $
#
# NetEx HyperIP Detection (SNMP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108349");
  script_version("$Revision: 8951 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-26 12:47:22 +0100 (Mon, 26 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-26 12:49:56 +0100 (Mon, 26 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NetEx HyperIP Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of a NetEx HyperIP
  virtual appliance.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port( default:161 );
sysdesc = get_snmp_sysdesc( port:port );
if( ! sysdesc || sysdesc !~ "^HyperIP" ) exit( 0 );

version = "unknown";

# HyperIP 6.1.1 11-Jan-2018 13:09 (build 2) (r9200)
vers = eregmatch( pattern:"^HyperIP ([0-9.]+)", string:sysdesc );
if( vers[1] ) version = vers[1];

set_kb_item( name:"hyperip/detected", value:TRUE );
set_kb_item( name:"hyperip/snmp/detected", value:TRUE );
set_kb_item( name:"hyperip/snmp/port", value:port );
set_kb_item( name:"hyperip/snmp/" + port + "/concluded", value:sysdesc );
set_kb_item( name:"hyperip/snmp/" + port + "/version", value:version );

exit( 0 );
