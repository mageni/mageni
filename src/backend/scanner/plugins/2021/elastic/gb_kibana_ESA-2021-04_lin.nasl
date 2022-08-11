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
  script_oid("1.3.6.1.4.1.25623.1.0.145384");
  script_version("2021-02-15T06:43:48+0000");
  script_tag(name:"last_modification", value:"2021-02-15 11:14:46 +0000 (Mon, 15 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-15 06:34:11 +0000 (Mon, 15 Feb 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2020-26296");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana < 6.8.14, 7.0.0 < 7.10.2 Vega XSS Vulnerability (ESA-2021-04) (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_detect_http.nasl", "os_detection.nasl");
  script_mandatory_keys("elastic/kibana/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Kibana is prone to a cross-site scripting vulnerability in Vega visualization.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Kibana 'Vega' visualization type is susceptible to both stored and
  reflected XSS via a vulnerable version of the Vega library.");

  script_tag(name:"impact", value:"Users who can create these visualizations or craft a vulnerable URL
  describing this visualization can execute arbitrary JavaScript in the victim's browser.");

  script_tag(name:"affected", value:"Kibana versions prior to 6.8.14 and 7.10.2.");

  script_tag(name:"solution", value:"Update to version 6.8.14, 7.10.2 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-11-0-and-6-8-14-security-update/263915");

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

if (version_is_less(version: version, test_version: "6.8.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.10.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.10.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
