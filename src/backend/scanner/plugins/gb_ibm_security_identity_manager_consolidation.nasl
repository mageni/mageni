# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.813523");
  script_version("2020-07-08T10:06:00+0000");
  script_tag(name:"last_modification", value:"2020-07-08 14:19:02 +0000 (Wed, 08 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-08 08:32:01 +0000 (Wed, 08 Jul 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IBM Security Identity Manager Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_security_identity_manager_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_ibm_security_identity_manager_ssh_login_detect.nasl");
  script_mandatory_keys("ibm/security_identity_manager/detected");

  script_tag(name:"summary", value:"Consolidation of IBM Security Identity Manager detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "ibm/security_identity_manager/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "ssh-login", "http" ) ) {

  install_list = get_kb_list( "ibm/security_identity_manager/" + source + "/*/installs" );
  if( ! install_list )
    continue;

  # nb: Note that sorting the array above is currently dropping the named array index
  install_list = sort( install_list );

  foreach install( install_list ) {

    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 3 )
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    install  = infos[1];
    version  = infos[2];
    concl    = infos[3];
    conclloc = infos[4];

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ibm:security_identity_manager:" );
    if( ! cpe )
      cpe = "cpe:/a:ibm:security_identity_manager";

    if( source == "http" ) {
      source = "www";
      extra = "Detected via HTTP";
    } else if( source == "ssh-login" ) {
      extra = "Detected via SSH login";
    }

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';
    report += build_detection_report( app:"IBM Security Identity Manager",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      extra:extra,
                                      concluded:concl,
                                      concludedUrl:conclloc );
  }
}

if( report )
  log_message( port:0, data:report );

exit( 0 );
