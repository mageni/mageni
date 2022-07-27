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
  script_oid("1.3.6.1.4.1.25623.1.0.113883");
  script_version("2022-04-07T07:22:10+0000");
  script_tag(name:"last_modification", value:"2022-04-07 07:22:10 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-06 08:06:40 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VMware Spring Boot Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_vmware_spring_boot_ssh_login_detect.nasl",
                      "gb_vmware_spring_boot_smb_login_detect.nasl");
  script_mandatory_keys("vmware/spring/boot/detected");

  script_tag(name:"summary", value:"Consolidation of VMware Spring Boot (and its components)
  detections.");

  script_xref(name:"URL", value:"https://spring.io/projects/spring-boot");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "vmware/spring/boot/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...
BASE_CPE = "cpe:/a:vmware:spring_boot";

foreach source( make_list( "ssh-login", "smb-login" ) ) {

  install_list = get_kb_list( "vmware/spring/boot/" + source + "/*/installs" );
  if( ! install_list )
    continue;

  # nb: Note that sorting the array above is currently dropping the named array index
  install_list = sort( install_list );

  foreach install( install_list ) {

    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 3 )
      continue; # Something went wrong and not all required infos are there...

    port    = infos[0];
    install = infos[1];
    version = infos[2];
    concl   = infos[3];

    comp = infos[4];
    # nb: Shouldn't happen, just as a fallback...
    if( ! comp ) {
      comp = "N/A";
      final_cpe = BASE_CPE + "_unknown_component";
    } else {
      comp = tolower( comp );
      if( comp == "core" )
        final_cpe = BASE_CPE;
      else
        final_cpe = BASE_CPE + "_" + comp;
    }

    cpe = build_cpe( value:version, exp:"^([0-9.x]+)", base:final_cpe + ":" );
    if( ! cpe )
      cpe = final_cpe;

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';
    report += build_detection_report( app:"VMware Spring Boot (Component: " + comp + ")",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concluded:concl );
  }
}

if( report )
  log_message( port:0, data:report );

exit( 0 );