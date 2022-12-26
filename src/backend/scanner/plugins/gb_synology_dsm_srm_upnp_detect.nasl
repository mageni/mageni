# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.170226");
  script_version("2022-12-01T10:11:22+0000");
  script_tag(name:"last_modification", value:"2022-12-01 10:11:22 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-11-14 22:03:50 +0000 (Mon, 14 Nov 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology DiskStation Manager (DSM) Detection (UPnP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_upnp_tcp_detect.nasl");
  script_mandatory_keys("upnp/tcp/port");

  script_tag(name:"summary", value:"UPnP based detection of Synology NAS devices, DiskStation Manager
  (DSM) OS and application.");

  exit(0);
}

include("host_details.inc");
include("synology_func.inc");

if( ! port = get_kb_item( "upnp/tcp/port" ) )
  exit( 0 );

if( ! vendor = get_kb_item( "upnp/tcp/" + port + "/device/manufacturer" ) )
  exit( 0 );

if( "Synology" >< vendor ) {

  model_nr = get_kb_item( "upnp/tcp/" + port + "/device/modelNumber" );
  if( model_nr ) {
    info = split( model_nr, sep:" ", keep:FALSE );
    model = info[0];
    if( model ) {
      # nb: UPnP looks the same for NAS and router devices from Synology
      # we need to filter by router models
      if( check_is_synology_router( model:model ) ) {
        # nb: Version for router (SRM OS) exposed via mDNS is not correct
        set_kb_item( name:"synology/srm/detected", value:TRUE );
        set_kb_item( name:"synology/srm/upnp/detected", value:TRUE );
        set_kb_item( name:"synology/srm/upnp/port", value:port );
        set_kb_item( name:"synology/srm/upnp/" + port + "/model", value:model );
        # nb: Ignore version for SRM as real examples showed it is false
      } else {
        set_kb_item(name:"synology/dsm/detected",value:TRUE);
        set_kb_item( name:"synology/dsm/upnp/detected", value:TRUE );
        set_kb_item( name:"synology/dsm/upnp/port", value:port );
        set_kb_item( name:"synology/dsm/upnp/" + port + "/model", value:model );
        if( info[1] )
          set_kb_item( name:"synology/dsm/upnp/" + port + "/version", value:info[1] );
      }
    }
  }
}

exit( 0 );
