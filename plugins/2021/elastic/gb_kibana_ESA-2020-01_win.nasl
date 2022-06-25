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

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117166");
  script_version("2021-01-19T12:17:47+0000");
  script_tag(name:"last_modification", value:"2021-01-20 11:07:43 +0000 (Wed, 20 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-19 11:49:14 +0000 (Tue, 19 Jan 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-15604", "CVE-2019-15605", "CVE-2019-15606");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana < 6.8.7, 7.x < 7.6.1 Multiple Vulnerabilities in Node.js (ESA-2020-01) (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_detect_http.nasl", "os_detection.nasl");
  script_mandatory_keys("elastic/kibana/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Kibana is prone to multiple vulnerabilities in the shipped 3rdparty
  Node.js component.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The version of Node.js shipped in Kibana contain three security flaws:

  - CVE-2019-15604 describes a Denial of Service (DoS) flaw in the TLS handling code of Node.js.
  Successful exploitation of this flaw could result in Kibana crashing.

  - CVE-2019-15606 and CVE-2019-15605 describe flaws in how Node.js handles malformed HTTP headers.
  These malformed headers could result in a HTTP request smuggling attack when Kibana is running behind
  a proxy vulnerable to HTTP request smuggling attacks.

  This update upgrades Node.js to version 10.19.0, which is not vulnerable to these issues.");

  script_tag(name:"affected", value:"Kibana versions prior to 6.8.7 and 7.6.1.");

  script_tag(name:"solution", value:"Update to version 6.8.7, 7.6.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-6-8-7-and-7-6-1-security-update/222136");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security");

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

if (version_is_less(version: version, test_version: "6.8.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.6.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
