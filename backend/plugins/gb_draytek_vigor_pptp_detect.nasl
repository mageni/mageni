# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108735");
  script_version("2020-04-03T11:15:15+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-04-06 12:43:58 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-02 08:40:07 +0000 (Thu, 02 Apr 2020)");
  script_name("DrayTek Vigor Detection (PPTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("pptp_detect.nasl");
  script_mandatory_keys("pptp/vendor_string/detected");

  script_tag(name:"summary", value:"Detection of DrayTek Vigor devices via PPTP.

  The script checks the vendor string of the device previously gathered via the PPTP Protocol and attempts to
  detect the presence of a DrayTek Vigor device.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service( default:1723, proto:"pptp" );

if( ! vendor = get_kb_item( "pptp/" + port + "/vendor_string" ) )
  exit( 0 );

if( ! hostname = get_kb_item( "pptp/" + port + "/hostname" ) )
  exit( 0 );

if( vendor !~ "DrayTek" || hostname !~ "Vigor" )
  exit( 0 );

version = "unknown";
concluded = '\n  - Vendor String: ' + vendor + '\n  - Hostname:      ' + hostname;

set_kb_item( name:"draytek/vigor/detected", value:TRUE );
set_kb_item( name:"draytek/vigor/pptp/detected", value:TRUE );
set_kb_item( name:"draytek/vigor/pptp/port", value:port );
set_kb_item( name:"draytek/vigor/pptp/" + port + "/concluded", value:concluded );
set_kb_item( name:"draytek/vigor/pptp/" + port + "/version", value:version );

exit( 0 );
