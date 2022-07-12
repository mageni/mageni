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

CPE = "cpe:/a:apache:log4j";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117902");
  script_version("2022-01-19T06:49:22+0000");
  script_tag(name:"last_modification", value:"2022-01-19 11:07:58 +0000 (Wed, 19 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-18 14:58:33 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-21 17:57:00 +0000 (Mon, 21 Jun 2021)");

  script_cve_id("CVE-2022-23302", "CVE-2022-23305", "CVE-2022-23307", "CVE-2020-9493");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Apache Log4j 1.x Multiple Vulnerabilities (Windows, Jan 2022) - Version Check");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apache_log4j_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/log4j/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Log4j is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-23302: Deserialization of untrusted data in JMSSink. Note this issue only affects Log4j
  1.x when specifically configured to use JMSSink, which is not the default.

  - CVE-2022-23305: SQL injection in JDBC Appender. Note this issue only affects Log4j 1.x when
  specifically configured to use the JDBCAppender, which is not the default.

  - CVE-2022-23307/CVE-2020-9493: A deserialization flaw in the Chainsaw component of Log4j 1.x can
  lead to malicious code execution.");

  script_tag(name:"affected", value:"Apache Log4j version 1.x.");

  script_tag(name:"solution", value:"No solution was made available by the vendor.

  Note: Apache Log4j 1.x reached end of life in August 2015. Users should upgrade to Log4j 2 as it
  addresses numerous other issues from the previous versions.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/01/18/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/01/18/4");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/01/18/5");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^1\.[0-2]") {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
