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
  script_oid("1.3.6.1.4.1.25623.1.0.108683");
  script_version("2019-10-22T09:18:17+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-10-22 09:18:17 +0000 (Tue, 22 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-22 09:14:32 +0000 (Tue, 22 Oct 2019)");
  script_name("MikroTik RouterOS Detection (PPTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("pptp_detect.nasl");
  script_mandatory_keys("pptp/vendor_string/detected");

  script_tag(name:"summary", value:"Detection of MikroTik RouterOS via PPTP.

  The script checks the vendor string of the device previously gathered via the PPTP Protocol and attempts to
  detect the presence of a MikroTik Router.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service( default:1723, proto:"pptp" );

if( ! banner = get_kb_item( "pptp/" + port + "/vendor_string" ) )
  exit( 0 );

if( banner !~ "MikroTik" )
  exit( 0 );

version = "unknown";

set_kb_item( name:"mikrotik/detected", value:TRUE );
set_kb_item( name:"mikrotik/pptp/detected", value:TRUE );
set_kb_item( name:"mikrotik/pptp/port", value:port );
set_kb_item( name:"mikrotik/pptp/" + port + "/concluded", value:banner );
set_kb_item( name:"mikrotik/pptp/" + port + "/version", value:version );

exit( 0 );
