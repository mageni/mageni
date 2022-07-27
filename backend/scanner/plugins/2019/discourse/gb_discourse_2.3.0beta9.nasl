# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108601");
  script_version("2019-06-18T06:52:36+0000");
  script_cve_id("CVE-2019-11358");
  script_tag(name:"last_modification", value:"2019-06-18 06:52:36 +0000 (Tue, 18 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-17 06:03:35 +0000 (Mon, 17 Jun 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Discourse < 2.3.0.beta9 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities in 3rdparty components.");

  script_tag(name:"insight", value:"The following 3rdparty components have been updated to fix security issues:

  - Jquery CVE-2019-11358

  - Update nokogiri

  - Update Handlebars to 4.1");

  script_tag(name:"affected", value:"Discourse before version 2.3.0.beta9.");

  script_tag(name:"solution", value:"Update to version 2.3.0.beta9.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://meta.discourse.org/t/discourse-2-3-0-beta9-release-notes/115786");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"2.3.0.beta9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.3.0.beta9", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );