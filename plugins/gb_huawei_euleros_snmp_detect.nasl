# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108557");
  script_version("2020-01-16T09:51:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-01-16 09:51:04 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-03-10 11:25:53 +0100 (Sun, 10 Mar 2019)");

  script_name("Huawei EulerOS Detection (SNMP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_get_installed_sw.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/installed_software/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Huawei EulerOS.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("snmp_func.inc");
include("host_details.inc");

port = get_snmp_port( default:161 );

# euleros-release-2.0SP2-6.x86_64
# nb: A default EulerOS doesn't provide access to the 1.3.6.1.2.1.25.6.3.1.2 tree
# but the SNMP service might still be re-configured to allow this.
if( ! infos = snmp_get_sw_oid( pattern:"euleros-release", port:port ) )
  exit( 0 );

package = infos["package"];
oid     = infos["oid"];

set_kb_item( name:"huawei/euleros/detected", value:TRUE );
set_kb_item( name:"huawei/euleros/snmp/detected", value:TRUE );
set_kb_item( name:"huawei/euleros/snmp/port", value:port );

vers_nd_sp = eregmatch( pattern:"euleros-release-([0-9]+\.[0-9]+)(SP([0-9]+))?", string:package );
if( vers_nd_sp[1] ) {
  set_kb_item( name:"huawei/euleros/snmp/" + port + "/version", value:vers_nd_sp[1] );

  if( vers_nd_sp[3] )
    set_kb_item( name:"huawei/euleros/snmp/" + port + "/sp", value:vers_nd_sp[3] );
  else
    set_kb_item( name:"huawei/euleros/snmp/" + port + "/sp", value:"0" );

  set_kb_item(name: "huawei/euleros/snmp/" + port + "/concluded", value:package );
  set_kb_item(name: "huawei/euleros/snmp/" + port + "/concludedOID", value:oid );
}

exit( 0 );
