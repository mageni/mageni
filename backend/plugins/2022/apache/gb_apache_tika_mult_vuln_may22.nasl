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

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148125");
  script_version("2022-05-17T10:59:25+0000");
  script_tag(name:"last_modification", value:"2022-05-18 09:49:57 +0000 (Wed, 18 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-17 03:04:07 +0000 (Tue, 17 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2022-25169", "CVE-2022-30126");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tika Server < 1.28.2, 2.x < 2.4.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_apache_tika_server_detect.nasl");
  script_mandatory_keys("Apache/Tika/Server/Installed");

  script_tag(name:"summary", value:"Apache Tika Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-25169: The BPG parser may allocate an unreasonable amount of memory on carefully
  crafted files

  - CVE-2022-30126: A regular expression in our StandardsText class, used by the
  StandardsExtractingContentHandler could lead to a denial of service caused by backtracking on a
  specially crafted file");

  script_tag(name:"affected", value:"Apache Tika Server prior to version 1.28.2 and version 2.x
  prior to 2.4.0.");

  script_tag(name:"solution", value:"Update to version 1.28.2, 2.4.0 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/t3tb51sf0k2pmbnzsrrrm23z9r1c10rk");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/dh3syg68nxogbmlg13srd6gjn3h2z6r4");

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

if (version_is_less(version: version, test_version: "1.28.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.28.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.0", test_version_up: "2.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
