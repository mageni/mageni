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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117903");
  script_version("2022-01-19T07:09:14+0000");
  script_tag(name:"last_modification", value:"2022-01-19 07:09:14 +0000 (Wed, 19 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-19 07:00:46 +0000 (Wed, 19 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-30 16:22:00 +0000 (Thu, 30 Dec 2021)");

  script_cve_id("CVE-2021-45105");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts 2.5.x < 2.5.28.2 Log4j DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_tag(name:"summary", value:"Apache Struts is prone to a denial of service (DoS)
  vulnerability in the Apache Log4j library.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache Log4j2 did not protect from uncontrolled recursion from
  self-referential lookups. When the logging configuration uses a non-default Pattern Layout with a
  Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map
  (MDC) input data can craft malicious input data that contains a recursive lookup, resulting in a
  StackOverflowError that will terminate the process.");

  script_tag(name:"affected", value:"Apache Struts version 2.5.x prior to 2.5.28.2.");

  script_tag(name:"solution", value:"Update to version 2.5.28.2 or later.");

  script_xref(name:"URL", value:"https://struts.apache.org/announce-2021#a20211223");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-p6xc-xr62-6r2g");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2.5.0", test_version_up: "2.5.28.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.28.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
