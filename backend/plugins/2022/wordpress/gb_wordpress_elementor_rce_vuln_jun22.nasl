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

CPE = "cpe:/a:elementor:elementor_page_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126058");
  script_version("2022-07-04T10:18:32+0000");
  script_tag(name:"last_modification", value:"2022-07-04 10:18:32 +0000 (Mon, 04 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-01 12:23:30 +0000 (Fri, 01 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-27 17:33:00 +0000 (Wed, 27 Apr 2022)");

  script_cve_id("CVE-2022-1329");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Elementor Page Builder Plugin 3.6.0 - 3.6.2 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/elementor/detected");

  script_tag(name:"summary", value:"The WordPress plugin Elementor Page Builder is prone
  to remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This vulnerability allows any authenticated user to upload arbitrary PHP code");

  script_tag(name:"affected", value:"WordPress Elementor Page Builder version 3.6.0
  through 3.6.2.");

  script_tag(name:"solution", value:"Update to version 3.6.3 or later.");

  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/changeset/2708766/elementor/trunk/core/app/modules/onboarding/module.php");
  script_xref(name:"URL", value:"https://www.pluginvulnerabilities.com/2022/04/12/5-million-install-wordpress-plugin-elementor-contains-authenticated-remote-code-execution-rce-vulnerability/");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2022/04/elementor-critical-remote-code-execution-vulnerability/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if ( version_in_range( version:version, test_version:"3.6.0", test_version2:"3.6.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit(99);
