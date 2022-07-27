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

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147751");
  script_version("2022-03-04T03:06:45+0000");
  script_tag(name:"last_modification", value:"2022-03-04 10:35:15 +0000 (Fri, 04 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-04 03:03:37 +0000 (Fri, 04 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:P/A:N");

  script_cve_id("CVE-2022-23710");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana XSS Vulnerability (ESA-2022-04)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_detect_http.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Elastic Kibana is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A cross-site scripting (XSS) vulnerability was discovered in
  the Data Preview Pane (previously known as Index Pattern Preview Pane) which could allow
  arbitrary JavaScript to be executed in a victim's browser.");

  script_tag(name:"affected", value:"Elastic Kibana version 7.15.0 through 7.17.0 and version
  8.0.0.");

  script_tag(name:"solution", value:"Update to version 7.17.1, 8.0.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-17-1-security-update/298447");

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

if (version_in_range(version: version, test_version: "7.15.0", test_version2: "7.17.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.17.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "8.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
