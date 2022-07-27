# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.112739");
  script_version("2020-05-05T10:09:51+0000");
  script_tag(name:"last_modification", value:"2020-05-06 11:41:12 +0000 (Wed, 06 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-05 09:22:00 +0000 (Tue, 05 May 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-6008");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress LifterLMS Plugin < 3.37.15 Arbitrary File Write Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("lifterlms/detected");

  script_tag(name:"summary", value:"LifterLMS plugin for WordPress is prone to an arbitrary file write vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability allows an attacker to change their profile name to a malicious piece of PHP code.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to steal personal information,
  change grades, retrieve tests and test answers beforehand, and also forge certificates by remotely executing arbitrary PHP code.");

  script_tag(name:"affected", value:"WordPress LifterLMS plugin before version 3.37.15.");

  script_tag(name:"solution", value:"Update to version 3.37.15 or later.");

  script_xref(name:"URL", value:"https://thehackernews.com/2020/04/wordpress-lms-plugins.html");
  script_xref(name:"URL", value:"https://research.checkpoint.com/2020/e-learning-platforms-getting-schooled-multiple-vulnerabilities-in-wordpress-most-popular-learning-management-system-plugins/");

  exit(0);
}

CPE = "cpe:/a:lifterlms:lifterlms";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.37.15" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.37.15", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
