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

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170207");
  script_version("2022-11-08T10:12:11+0000");
  script_tag(name:"last_modification", value:"2022-11-08 10:12:11 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-10-14 13:56:28 +0000 (Fri, 14 Oct 2022)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Trihedral VTScada Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_trihedral_vtscada_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_trihedral_vtscada_smb_login_detect.nasl");
  script_mandatory_keys("trihedral/vtscada/detected");

  script_tag(name:"summary", value:"Consolidation of Trihedral VTScada detections.");

  script_xref(name:"URL", value:"http://www.trihedral.com");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if ( ! get_kb_item( "trihedral/vtscada/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "http", "smb-login") ) {

  install_list = get_kb_list( "trihedral/vtscada/" + source + "/*/installs" );

  if ( ! install_list )
    continue;

  install_list = sort( install_list );

  foreach install ( install_list ) {
    infos = split( install, sep:"#---#", keep:FALSE );
    if ( max_index( infos ) < 4 )
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    app      = infos[1];
    install  = infos[2];
    version  = infos[3];
    concl    = infos[4];
    conclurl = infos[5];

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:trihedral:vtscada:" );
    if ( ! cpe )
      cpe = "cpe:/a:trihedral:vtscada";

    if( source == "http" )
      source = "www";

    register_product( cpe:cpe, location:install, port:port, service:source );

    if ( report )
      report += '\n\n';

    report += build_detection_report( app:app, version:version, install:install,
                                      cpe:cpe, concluded:concl, concludedUrl:conclurl );
  }
}

log_message( port:0, data:chomp( report ) );

exit( 0 );