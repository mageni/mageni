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

CPE = "cpe:/a:strategy11:formidable";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147082");
  script_version("2021-11-03T14:03:41+0000");
  script_tag(name:"last_modification", value:"2021-11-03 14:03:41 +0000 (Wed, 03 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-03 07:09:34 +0000 (Wed, 03 Nov 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-27 18:06:00 +0000 (Wed, 27 Oct 2021)");

  script_cve_id("CVE-2021-24608", "CVE-2021-39330");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Formidable Forms Builder Plugin < 5.0.07 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/formidable/detected");

  script_tag(name:"summary", value:"The WordPress plugin Formidable Forms Builder is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-24608: Stored cross-site scripting (XSS)

  - CVE-2021-39330: Stored cross-site scripting (XSS)");

  script_tag(name:"affected", value:"WordPress Formidable Forms Builder version 5.0.06 and prior.");

  script_tag(name:"solution", value:"Update to version 5.0.07 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/75305ea8-730b-4caf-a3c6-cb94adee683c");
  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2021-39330");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/Strategy11/formidable-forms/master/changelog.txt");

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

if (version_is_less(version: version, test_version: "5.0.07")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.07", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
