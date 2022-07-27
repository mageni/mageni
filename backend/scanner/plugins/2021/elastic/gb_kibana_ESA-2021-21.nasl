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
  script_oid("1.3.6.1.4.1.25623.1.0.117698");
  script_version("2021-09-27T11:52:39+0000");
  script_tag(name:"last_modification", value:"2021-09-28 10:14:46 +0000 (Tue, 28 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-27 11:31:59 +0000 (Mon, 27 Sep 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2021-22150");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana Code Execution Vulnerability (ESA-2021-21)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_detect_http.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Elastic Kibana is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a user with fleet admin permissions could
  upload a malicious package. Due to using an older version of the js-yaml library, this package
  would be loaded in an insecure manner, allowing an attacker to execute commands on the kibana
  server.");

  script_tag(name:"affected", value:"Elastic Kibana versions 7.10.2 through 7.14.0.");

  script_tag(name:"solution", value:"Update to version 7.14.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-14-1-security-update/283077");

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

if (version_in_range(version: version, test_version: "7.10.2", test_version2: "7.14.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.14.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);