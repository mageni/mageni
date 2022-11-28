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
  script_oid("1.3.6.1.4.1.25623.1.0.148935");
  script_version("2022-11-22T10:12:16+0000");
  script_tag(name:"last_modification", value:"2022-11-22 10:12:16 +0000 (Tue, 22 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-21 10:13:30 +0000 (Mon, 21 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2021-22142");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana Reporting Vulnerability (ESA-2021-13)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_detect_http.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Elastic Kibana is prone to a reporting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Kibana contains an embedded version of the Chromium browser
  that the Reporting feature uses to generate the downloadable reports. If a user with permissions
  to generate reports is able to render arbitrary HTML with this browser, they may be able to
  leverage known Chromium vulnerabilities to conduct further attacks. Kibana contains a number of
  protections to prevent this browser from rendering arbitrary content.");

  script_tag(name:"affected", value:"Elastic Kibana version 7.x pior to 7.13.0.");

  script_tag(name:"solution", value:"Update to version 7.13.0 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-13-0-and-6-8-16-security-update/273964");

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

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.13.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.13.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
