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
  script_oid("1.3.6.1.4.1.25623.1.0.113818");
  script_version("2021-05-28T10:08:24+0000");
  script_tag(name:"last_modification", value:"2021-05-31 10:47:15 +0000 (Mon, 31 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-28 09:43:02 +0000 (Fri, 28 May 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-14827");

  script_name("Moodle <= 3.5.7, 3.6.x <= 3.6.5, 3.7.x <= 3.7.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is exploitable via recursive rendering from contexts
  in some Mustache templates.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker
  to inject arbitrary JavaScript into the site.");

  script_tag(name:"affected", value:"Moodle through version 3.5.7, versions 3.6.0 through 3.6.5 and 3.7.0 through 3.7.1.");

  script_tag(name:"solution", value:"Update to version 3.5.8, 3.6.6 or 3.7.2 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=391030");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.5.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.8", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.6.0", test_version2: "3.6.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.6.6", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.7.0", test_version2: "3.7.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.7.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );