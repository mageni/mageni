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
  script_oid("1.3.6.1.4.1.25623.1.0.104436");
  script_version("2022-11-24T16:43:59+0000");
  script_tag(name:"last_modification", value:"2022-11-24 16:43:59 +0000 (Thu, 24 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-24 14:27:54 +0000 (Thu, 24 Nov 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apache Commons Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_apache_commons_ssh_login_detect.nasl");
  script_mandatory_keys("apache/commons/detected");

  script_tag(name:"summary", value:"Consolidation of Apache Commons (and its components)
  detections.");

  script_xref(name:"URL", value:"https://commons.apache.org/");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "apache/commons/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...
BASE_CPE = "cpe:/a:apache:commons";

foreach source( make_list( "ssh-login" ) ) {

  install_list = get_kb_list( "apache/commons/" + source + "/*/installs" );
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

      if( comp == "core" ) {
        final_cpe = BASE_CPE;
      } else {
        final_cpe = BASE_CPE + "_" + comp;
        # nb: In the NVD a lower dash between product and component (e.g. commons_text) is used so
        # we're doing the same here BUT only for the CPE and not at other places like the component
        # name in the reporting or the KB keys in the other detection VTs.
        final_cpe = str_replace( string:final_cpe, find:"-", replace:"_" );
      }
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:final_cpe + ":" );
    if( ! cpe )
      cpe = final_cpe;

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';
    report += build_detection_report( app:"Apache Commons (Component: " + comp + ")",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concluded:concl );
  }
}

if( report )
  log_message( port:0, data:report );

exit( 0 );
