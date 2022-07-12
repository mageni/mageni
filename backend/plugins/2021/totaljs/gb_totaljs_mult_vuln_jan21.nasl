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

CPE = "cpe:/a:totaljs:total.js";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145327");
  script_version("2021-02-08T02:35:06+0000");
  script_tag(name:"last_modification", value:"2021-02-08 11:02:13 +0000 (Mon, 08 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-08 02:21:31 +0000 (Mon, 08 Feb 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-28494", "CVE-2020-28495");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Total.js < 3.4.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_totaljs_detect.nasl");
  script_mandatory_keys("totaljs/detected");

  script_tag(name:"summary", value:"Total.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Command injection (CVE-2020-28494)

  - Prototype pollution (CVE-2020-28495)");

  script_tag(name:"affected", value:"Total.js prior to version 3.4.7.");

  script_tag(name:"solution", value:"Update to version 3.4.7 or later.");

  script_xref(name:"URL", value:"https://github.com/totaljs/framework/commit/6192491ab2631e7c1d317c221f18ea613e2c18a5");
  script_xref(name:"URL", value:"https://snyk.io/vuln/SNYK-JS-TOTALJS-1046672");
  script_xref(name:"URL", value:"https://github.com/totaljs/framework/commit/b3f901561d66ab799a4a99279893b94cad7ae4ff");
  script_xref(name:"URL", value:"https://snyk.io/vuln/SNYK-JS-TOTALJS-1046671");

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

if (version_is_less(version: version, test_version: "3.4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
