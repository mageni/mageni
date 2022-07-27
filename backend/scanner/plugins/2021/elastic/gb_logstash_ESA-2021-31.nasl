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

CPE = "cpe:/a:elastic:logstash";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147312");
  script_version("2021-12-20T12:20:30+0000");
  script_tag(name:"last_modification", value:"2021-12-20 12:20:30 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-13 05:03:51 +0000 (Mon, 13 Dec 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 01:15:00 +0000 (Tue, 14 Dec 2021)");

  script_cve_id("CVE-2021-44228");

  # The Logstash version might differ from the Elasticsearch version detected
  # by gb_elastic_elasticsearch_detect_http.nasl
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Logstash Log4j RCE Vulnerability (ESA-2021-31, Log4Shell)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl");
  script_mandatory_keys("elastic/logstash/detected");

  script_tag(name:"summary", value:"Elastic Logstash is prone to a remote code execution (RCE)
  vulnerability in the Apache Log4j library dubbed 'Log4Shell'.");

  script_tag(name:"insight", value:"Apache Log4j2 JNDI features used in configuration, log messages,
  and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.
  An attacker who can control log messages or log message parameters can execute arbitrary code
  loaded from LDAP servers when message lookup substitution is enabled.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Elastic Logstash version 5.x through 7.x.");

  script_tag(name:"solution", value:"Update to version 6.8.21, 7.16.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/apache-log4j2-remote-code-execution-rce-vulnerability-cve-2021-44228-esa-2021-31/291476");
  script_xref(name:"URL", value:"https://discuss.elastic.co/t/logstash-5-0-0-6-8-20-and-7-0-0-7-16-0-log4j-cve-2021-44228-cve-2021-45046-remediation/292343");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-jfh8-c2jp-5v3q");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/12/10/1");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day/");

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

if (version_in_range(version: version, test_version: "5.0", test_version2: "6.8.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.16.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.16.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
