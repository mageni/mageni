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

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117851");
  script_version("2021-12-22T03:03:20+0000");
  script_tag(name:"last_modification", value:"2021-12-22 11:14:08 +0000 (Wed, 22 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-20 11:29:44 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-21 00:15:00 +0000 (Tue, 21 Dec 2021)");

  script_cve_id("CVE-2021-45046", "CVE-2021-45105");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch Multiple Log4j Vulnerabilities (Dec 2021)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"Elastic Elasticsearch is prone to multiple vulnerabilities in
  the Apache Log4j library.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  CVE-2021-45046: Denial of Service (DoS) and a possible remote code execution (RCE) in certain
  non-default configurations.

  CVE-2021-45105: Apache Log4j2 did not protect from uncontrolled recursion from self-referential
  lookups. When the logging configuration uses a non-default Pattern Layout with a Context Lookup
  (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data
  can craft malicious input data that contains a recursive lookup, resulting in a StackOverflowError
  that will terminate the process.");

  script_tag(name:"impact", value:"The vendor states that there is no impact in all currently
  supported versions with default configurations. To avoid unknown risks it is still recommended to
  apply the updates or workarounds provided by the vendor.");

  script_tag(name:"affected", value:"Elastic Elasticsearch version 5.x through 7.x.");

  script_tag(name:"solution", value:"Update to version 6.8.22, 7.16.2 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/apache-log4j2-remote-code-execution-rce-vulnerability-cve-2021-44228-esa-2021-31/291476");
  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elasticsearch-5-0-0-5-6-10-and-6-0-0-6-3-2-log4j-cve-2021-44228-cve-2021-45046-remediation/292054");
  script_xref(name:"URL", value:"https://logging.apache.org/log4j/2.x/security.html");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day-update-on-cve-2021-45046/");

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

if (version_in_range(version: version, test_version: "5.0", test_version2: "6.8.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.16.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.16.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);