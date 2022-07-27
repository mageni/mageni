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

CPE = "cpe:/a:phpipam:phpipam";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147498");
  script_version("2022-01-21T03:05:45+0000");
  script_tag(name:"last_modification", value:"2022-01-21 11:28:09 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-21 03:00:22 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:P");

  script_cve_id("CVE-2022-23045", "CVE-2022-23046");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpIPAM < 1.4.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ipam_detect.nasl");
  script_mandatory_keys("phpipam/installed");

  script_tag(name:"summary", value:"phpIPAM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-23045: Stored XSS in the 'Site title' parameter

  - CVE-2022-23046: SQL injection (SQLi) in the 'subnet' parameter

  - XSS while uploading CVS files

  - XSS (reflected) in 'find subnets'");

  script_tag(name:"affected", value:"phpIPAM version 1.4.4 and prior.");

  script_tag(name:"solution", value:"Update to version 1.4.5 or later.");

  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/releases/tag/v1.4.5");
  script_xref(name:"URL", value:"https://fluidattacks.com/advisories/osbourne/");
  script_xref(name:"URL", value:"https://fluidattacks.com/advisories/mercury/");

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

if (version_is_less(version: version, test_version: "1.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
