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

CPE = "cpe:/a:wpmet:elements_kit_elementor_addons";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145952");
  script_version("2021-05-17T12:03:02+0000");
  script_tag(name:"last_modification", value:"2021-05-18 10:15:22 +0000 (Tue, 18 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-17 04:35:28 +0000 (Mon, 17 May 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2021-24258");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Elements Kit Plugin < 2.2.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/elementskit-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin Elements Kit is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Elements Kit Lite and Pro plugins have a number of widgets
  that are vulnerable to stored XSS by lower-privileged users such as contributors, all via a
  similar method.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"WordPress Elements Kit Lite and Pro plugins prior to version
  2.2.0.");

  script_tag(name:"solution", value:"Update to version 2.2.0 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/47b47b86-899b-4de3-8a3c-2d5d1774298f");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/elementskit-lite/#developers");

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

if (version_is_less(version: version, test_version: "2.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
