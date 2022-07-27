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

CPE = "cpe:/a:roundcube:webmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144243");
  script_version("2020-07-15T08:03:52+0000");
  script_tag(name:"last_modification", value:"2020-07-15 11:30:14 +0000 (Wed, 15 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-15 07:43:19 +0000 (Wed, 15 Jul 2020)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2020-15562");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail XSS Vulnerability - July20");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_detect.nasl");
  script_mandatory_keys("roundcube/detected");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to a cross-site scripting vulnerability.");

  script_tag(name:"insight", value:"An issue was discovered in Roundcube Webmail which allows XSS via a crafted
  HTML e-mail message, as demonstrated by a JavaScript payload in the xmlns (aka XML namespace) attribute of a
  HEAD element when an SVG element exists.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Roundcube Webmail versions before 1.2.11, 1.3.14 and 1.4.7.");

  script_tag(name:"solution", value:"Update to version 1.2.11, 1.3.14, 1.4.7 or later.");

  script_xref(name:"URL", value:"https://roundcube.net/news/2020/07/05/security-updates-1.4.7-1.3.14-and-1.2.11");

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

if (version_is_less(version: version, test_version: "1.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.3", test_version2: "1.3.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.4", test_version2: "1.4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
