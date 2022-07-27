# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:avaya:ip_office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144380");
  script_version("2020-08-10T08:44:26+0000");
  script_tag(name:"last_modification", value:"2020-08-10 09:56:18 +0000 (Mon, 10 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-10 08:40:53 +0000 (Mon, 10 Aug 2020)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2019-7005");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Avaya IP Office 10.x < 10.1.0.8, 11.0 < 11.0.4.3 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_avaya_ip_office_detect.nasl");
  script_mandatory_keys("avaya/ip_office/detected");

  script_tag(name:"summary", value:"Avaya IP Office is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in the web interface component of IP Office
  that could potentially allow an unauthenticated user to gain access to sensitive information.");

  script_tag(name:"affected", value:"Avaya IP Office versions 10.0 through 10.1.0.7 and 11.0 through 11.0.4.2.");

  script_tag(name:"solution", value:"Update to version 10.1.0.8, 11.0.4.3 or later.");

  script_xref(name:"URL", value:"https://downloads.avaya.com/css/P8/documents/101070158");

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

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.1.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.0.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
