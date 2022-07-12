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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113710");
  script_version("2020-07-14T10:43:52+0000");
  script_tag(name:"last_modification", value:"2020-07-14 10:43:52 +0000 (Tue, 14 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-06 10:46:44 +0200 (Mon, 06 Jul 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Ruby Detection (Consolidation)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_ruby_rails_detect.nasl", "secpod_ruby_detect_lin.nasl",
                      "secpod_ruby_detect_win.nasl", "gb_ruby_webrick_detect.nasl");
  script_mandatory_keys("ruby/detected");

  script_tag(name:"summary", value:"Consolidates and reports the detected Ruby installation(s).");

  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/");

  exit(0);
}

if( ! get_kb_item( "ruby/detected" ) )
  exit( 0 );

CPE_base = "cpe:/a:ruby-lang:ruby";

include( "host_details.inc" );
include( "cpe.inc" );

report = "";

foreach proto( make_list( "ssh-login", "http", "smb-login" ) ) {
  install_list = get_kb_list( "ruby/" + proto + "/*/install" );
  if( ! install_list )
    continue;

  foreach install( install_list ) {
    infos = split( install, sep: "#---#", keep: FALSE );
    if( max_index( infos ) < 3 )
      continue;

    port = infos[0];
    location = infos[1];
    version = infos[2];
    concluded = infos[3];
    conclLocation = infos[4];

    if( ! cpe = build_cpe( value: version, exp: "([0-9.]+)", base: CPE_base + ":" ) )
      cpe = CPE_base;
    report_proto = proto;
    if( proto == "http" )
      report_proto = "www";
    register_product( cpe: cpe, location: location, port: port, service: report_proto );

    if( proto == "http" )
      extra = '\nDetected via HTTP';
    else if( proto == "ssh-login" )
      extra = '\nDetected via SSH login';
    else if( proto == "smb-login" )
      extra = '\nDetected via SMB login';

    extra += " on port " + port + "/tcp";

    if( report )
      report += '\n\n';

    report += build_detection_report( app: "Ruby",
                                      version: version,
                                      install: location,
                                      cpe: cpe,
                                      concluded: concluded,
                                      concludedUrl: conclLocation,
                                      extra: extra );
  }
}

if( report )
  log_message( data: report, port: 0 );

exit( 0 );
