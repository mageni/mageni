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
  script_oid("1.3.6.1.4.1.25623.1.0.145943");
  script_version("2021-12-20T12:20:30+0000");
  script_tag(name:"last_modification", value:"2021-12-20 12:20:30 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-05-14 06:15:01 +0000 (Fri, 14 May 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 10:15:00 +0000 (Tue, 29 Jun 2021)");

  script_cve_id("CVE-2021-22138");

  # The Logstash version might differ from the Elasticsearch version detected
  # by gb_elastic_elasticsearch_detect_http.nasl
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Logstash Certificate Verification Bypass Vulnerability (ESA-2021-09)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl");
  script_mandatory_keys("elastic/logstash/detected");

  script_tag(name:"summary", value:"Elastic Logstash is prone to a certificate verification bypass
  vulnerability.");

  script_tag(name:"insight", value:"A TLS certificate validation flaw was found in the monitoring
  feature of Logstash. When specifying a trusted server CA certificate Logstash would not properly
  verify the certificate returned by the monitoring server.");

  script_tag(name:"impact", value:"This could result in a man in the middle style attack against
  the Logstash monitoring data.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Elastic Logstash version 6.4.0 through 6.8.14 and 7.x prior to
  7.12.0.");

  script_tag(name:"solution", value:"Update to version 6.8.15, 7.12.0 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-12-0-and-6-8-15-security-update/268125");

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

if (version_in_range(version: version, test_version: "6.4.0", test_version2: "6.8.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^7\." && version_is_less(version: version, test_version: "7.12.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.12.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
