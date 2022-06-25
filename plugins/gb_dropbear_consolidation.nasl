# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112869");
  script_version("2021-02-26T12:02:34+0000");
  script_tag(name:"last_modification", value:"2021-03-02 12:14:25 +0000 (Tue, 02 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-02-26 10:57:11 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Dropbear Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("gb_dropbear_ssh_login_detect.nasl", "gb_dropbear_ssh_detect.nasl");
  script_mandatory_keys("dropbear_ssh/detected");

  script_xref(name:"URL", value:"https://matt.ucc.asn.au/dropbear/dropbear.html");

  script_tag(name:"summary", value:"Consolidation of Dropbear detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "dropbear_ssh/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "ssh-login", "ssh" ) ) {

  install_list = get_kb_list( "dropbear_ssh/" + source + "/*/installs" );
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

    # Dropbear v2018.76
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:dropbear_ssh_project:dropbear_ssh:" );
    if( ! cpe )
      cpe = "cpe:/a:dropbear_ssh_project:dropbear_ssh";

    register_product( cpe:cpe, location:install, port:port, service:source );

    # nb: Dropbear runs only on Unix-like OS variants
    register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", port:port, desc:"Dropbear Detection Consolidation", runs_key:"unixoide" );

    if( report )
      report += '\n\n';
    report += build_detection_report( app:"Dropbear SSH",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concluded:concl );
  }
}

if( report )
  log_message( port:0, data:report );

exit( 0 );
