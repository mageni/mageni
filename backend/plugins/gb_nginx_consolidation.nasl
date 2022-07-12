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
  script_oid("1.3.6.1.4.1.25623.1.0.113787");
  script_version("2021-02-01T12:59:26+0000");
  script_tag(name:"last_modification", value:"2021-02-02 11:22:57 +0000 (Tue, 02 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-01-26 14:11:11 +0100 (Tue, 26 Jan 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("nginx Detection (Consolidation)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_nginx_http_detect.nasl", "gb_nginx_ssh_login_detect.nasl");
  script_mandatory_keys("nginx/detected");

  script_tag(name:"summary", value:"Consolidation of nginx detections.");

  script_xref(name:"URL", value:"https://www.nginx.com/");

  exit(0);
}

if( ! get_kb_item( "nginx/detected" ) )
  exit( 0 );

include("host_details.inc");
include("cpe.inc");

report = ""; # nb: To make openvas-nasl-lint happy...

foreach proto( make_list( "ssh-login", "http" ) ) {

  install_list = get_kb_list( "nginx/" + proto + "/*/installs" );
  if( ! install_list )
    continue;

  # nb: Note that sorting the array above is currently dropping the named array index
  install_list = sort( install_list );

  foreach install( install_list ) {

    infos = split( install, sep: "#---#", keep: FALSE );
    if( max_index( infos ) != 4 )
      continue; # Something went wrong and not all required infos are there...

    port    = infos[0];
    install = infos[1];
    version = infos[2];
    concl   = infos[3];

    cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:nginx:nginx:" );
    if( ! cpe )
      cpe = "cpe:/a:nginx:nginx";

    if( proto == "http" )
      service = "www";
    else
      service = proto;

    register_product( cpe: cpe, location: install, port:port, service: service );

    if( report )
      report += '\n\n';
    report += build_detection_report( app: "nginx",
                                      version: version,
                                      install: install,
                                      cpe: cpe,
                                      concluded: concl );
  }
}

if( report )
  log_message( port: 0, data: report );

exit( 0 );
