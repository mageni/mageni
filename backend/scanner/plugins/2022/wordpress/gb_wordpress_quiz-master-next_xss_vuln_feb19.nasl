# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:expresstech:quiz-master-next";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127107");
  script_version("2022-07-30T07:26:17+0000");
  script_tag(name:"last_modification", value:"2022-07-30 07:26:17 +0000 (Sat, 30 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-29 13:11:08 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-9575");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("WordPress Quiz And Survey Master Plugin <= 6.0.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/quiz-master-next/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Quiz And Survey Master' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to reflected
  XSS as it echoes the quiz_id parameter without proper encoding.");

  script_tag(name:"affected", value:"WordPress Quiz And Survey Master plugin version 6.0.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://security-consulting.icu/blog/2019/02/wordpress-quiz-and-survey-master-xss/");
  script_xref(name:"URL", value:"https://lists.openwall.net/full-disclosure/2019/02/05/5");

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

if( version_is_less_equal( version: version, test_version: "6.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
