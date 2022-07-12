# Copyright (C) 2020 Greenbone Networks GmbH
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


if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112708");
  script_version("2020-02-28T13:16:52+0000");
  script_tag(name:"last_modification", value:"2020-02-28 13:16:52 +0000 (Fri, 28 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-28 13:09:11 +0000 (Fri, 28 Feb 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2020-9335");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Photo Gallery Plugin < 1.5.46 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("photo-gallery/detected");

  script_tag(name:"summary", value:"WordPress Photo Gallery plugin is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability would allow an
  authenticated admin user to inject arbitrary JavaScript code that is viewed by other users.");

  script_tag(name:"affected", value:"WordPress Photo Gallery plugin before 1.5.46.");

  script_tag(name:"solution", value:"Update to version 1.5.46 or later.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/10088");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/photo-gallery/#developers");

  exit(0);
}

CPE = "cpe:/a:10web:photo-gallery";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version: version, test_version: "1.5.46" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.46", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
