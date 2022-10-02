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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170180");
  script_version("2022-09-30T10:11:44+0000");
  script_tag(name:"last_modification", value:"2022-09-30 10:11:44 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-19 19:18:51 +0000 (Mon, 19 Sep 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apereo Central Authentication Service (CAS) Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Apereo (formerly Jasig) Central Authentication
  Service (CAS) detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_jasig_apereo_cas_detect_http.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_jasig_apereo_cas_smb_login_detect.nasl",
                        "gsf/gb_jasig_apereo_cas_ssh_login_detect.nasl");
  script_mandatory_keys("jasig_apereo/cas/detected");

  script_xref(name:"URL", value:"https://apereo.github.io/cas");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if ( ! get_kb_item( "jasig_apereo/cas/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "http", "ssh-login", "smb-login" ) ) {

  install_list = get_kb_list( "jasig_apereo/cas/" + source + "/*/installs" );

  if ( ! install_list )
    continue;

  install_list = sort( install_list );

  foreach install( install_list ) {
    infos = split( install, sep:"#---#", keep:FALSE );
    if ( max_index( infos ) < 3 )
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    install  = infos[1];
    version  = infos[2];
    concl    = infos[3];
    conclurl = infos[4];
    extra    = infos[5];

    # nb: The same product is currently tracked via different CPEs within the NVD...
    cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apereo:central_authentication_service:" );
    cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apereo:cas_server:" );

    if( ! cpe1 ) {
      cpe1 = "cpe:/a:apereo:central_authentication_service";
      cpe2 = "cpe:/a:apereo:cas_server";
    }

    if( source == "http" )
      source = "www";

    register_product( cpe:cpe1, location:install, port:port, service:source );
    register_product( cpe:cpe2, location:install, port:port, service:source );

    if( report )
      report += '\n\n';

    report += build_detection_report( app:"Jasig / Apereo Central Authentication Service (CAS)",
                                      version:version,
                                      install:install,
                                      cpe:cpe1,
                                      extra:extra,
                                      concludedUrl:conclurl,
                                      concluded:concl );
  }
}

log_message( port:0, data:chomp( report ) );

exit( 0 );
