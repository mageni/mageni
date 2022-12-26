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

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127282");
  script_version("2022-12-15T11:47:18+0000");
  script_tag(name:"last_modification", value:"2022-12-15 11:47:18 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-15 08:45:46 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2022-43707", "CVE-2022-43708", "CVE-2022-43709");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB < 1.8.32 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"summary", value:"MyBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-43707: Cross-site scripting (XSS) vulnerability in the visual MyCode editor (SCEditor)
  allows remote attackers to inject HTML via user input or stored data.

  - CVE-2022-43708: Multiple cross-site scripting (XSS) vulnerabilities in the post Attachments
  interface allow attackers to inject HTML by persuading the user to upload a file with specially
  crafted name.

  - CVE-2022-43709: SQL injection vulnerability in the Admin CP's Users module allows remote
  authenticated users to modify the query string via direct user input or stored search filter
  settings.");

  script_tag(name:"affected", value:"MyBB prior to version 1.8.32.");

  script_tag(name:"solution", value:"Update to version 1.8.32 or later.");

  script_xref(name:"URL", value:"https://github.com/mybb/mybb/security/advisories/GHSA-6vpw-m83q-27px");
  script_xref(name:"URL", value:"https://github.com/mybb/mybb/security/advisories/GHSA-p9m7-9qv4-x93w");
  script_xref(name:"URL", value:"https://github.com/mybb/mybb/security/advisories/GHSA-ggp5-454p-867v");


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

if (version_is_less(version: version, test_version: "1.8.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
