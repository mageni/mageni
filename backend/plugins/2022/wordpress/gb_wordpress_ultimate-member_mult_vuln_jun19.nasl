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

CPE = "cpe:/a:ultimatemember:ultimate-member";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127085");
  script_version("2022-07-15T06:04:25+0000");
  script_tag(name:"last_modification", value:"2022-07-15 06:04:25 +0000 (Fri, 15 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-13 14:14:15 +0000 (Wed, 13 Jul 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-24 13:14:00 +0000 (Mon, 24 Jun 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-10270", "CVE-2019-10271");

  script_name("WordPress Ultimate Member Plugin < 2.0.40 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ultimate-member/detected");

  script_tag(name:"summary", value:"The WordPress plugin Ultimate Member is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-10270: The plugin allows to reset the password of another user due to lack of
  verification and correlation between the reset password link key sent by mail and the
  user_id parameter.

  - CVE-2019-10271:The plugin allows unauthorized profile and cover picture modification. As a
  connected and authenticated user it is possible to modify the profile and cover picture of any
  user.");

  script_tag(name:"affected", value:"WordPress Ultimate Member plugin prior to version 2.0.40.");

  script_tag(name:"solution", value:"Update to version 2.0.40 or later.");

  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2019060101");
  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2019060120");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/ultimate-member/#developers");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
    exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
    exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.0.40" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.40", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
