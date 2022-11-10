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
  script_oid("1.3.6.1.4.1.25623.1.0.170203");
  script_version("2022-11-02T10:36:36+0000");
  script_tag(name:"last_modification", value:"2022-11-02 10:36:36 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-10-25 11:21:01 +0000 (Tue, 25 Oct 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology DiskStation Manager (DSM) Detection (mdNS)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("remote-detect-MDNS.nasl");
  script_require_udp_ports("Services/udp/mdns", 5353);

  script_tag(name:"summary", value:"mDNS based detection of Synology NAS devices, DiskStation Manager
  (DSM) OS and application.");

  exit(0);
}

include("host_details.inc");

if( ! vendor = get_kb_item( "mdns/info/vendor" ) )
  exit( 0 );

if( "Synology" >< vendor ) {

  # nb: In case of Synology, model is always advertised for the 5000/tpc service;
  # the model for _device_info service seems to always be Xserve, which does not help
  model = get_kb_item( "mdns/services/_http._tcp.local/info/model" );
  if( model ) {
    port = get_kb_item( "mdns/services/_http._tcp.local/info/admin_port" );

    if( ! isnull( port ) ) {
      # nb: mDNS looks the same for NAS and router devices from Synology
      # we need to filter by router models
      if( "MR2200ac" >< model || model =~ "^RT" ) {
        # nb: Version for router (SRM OS) exposed via mDNS is not correct
        set_kb_item(name:"synology/srm/detected",value:TRUE);
        set_kb_item( name:"synology/srm/mdns/detected", value:TRUE );
        set_kb_item( name:"synology/srm/mdns/port", value:port );
        set_kb_item( name:"synology/srm/mdns/" + port + "/model", value:model );
      } else {
          set_kb_item(name:"synology/dsm/detected",value:TRUE);
          set_kb_item( name:"synology/dsm/mdns/detected", value:TRUE );
          set_kb_item( name:"synology/dsm/mdns/port", value:port );
          set_kb_item( name:"synology/dsm/mdns/" + port + "/model", value:model );

          major_vers = get_kb_item( "mdns/services/_http._tcp.local/info/version_major" );
          minor_vers = get_kb_item( "mdns/services/_http._tcp.local/info/version_minor" );
          build_nr = get_kb_item( "mdns/services/_http._tcp.local/info/version_build" );

          # nb: version collected this way is less exact, as there is no micro part of it (although it is not always present)
          if( ! isnull( major_vers ) ) {
            version = major_vers;
            if( ! isnull( minor_vers ) )
              version += "." + minor_vers;
            if( ! isnull( build_nr ) )
              version += "-" + build_nr;
             set_kb_item( name:"synology/dsm/mdns/" + port + "/version", value:version );
          }
          serial = get_kb_item( "mdns/services/_http._tcp.local/info/serial" );
          if( serial )
            set_kb_item( name:"synology/dsm/mdns/" + port + "/serial", value:serial );
      }
    }
  }
}

exit( 0 );
