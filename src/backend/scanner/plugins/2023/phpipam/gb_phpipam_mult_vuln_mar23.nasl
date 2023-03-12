# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.126377");
  script_version("2023-03-09T10:09:20+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:20 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-08 10:28:10 +0000 (Wed, 08 Mar 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2023-1211", "CVE-2023-1212");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpIPAM < 1.5.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ipam_detect.nasl");
  script_mandatory_keys("phpipam/installed");

  script_tag(name:"summary", value:"phpIPAM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-1211: SQL Injection in Custom Fields in phpipam/phpipam

  - CVE-2023-1212: Two Stored XSS in Instructions and User Widget in phpipam/phpipam");

  script_tag(name:"affected", value:"phpIPAM prior to version 1.5.2.");

  script_tag(name:"solution", value:"Update to version 1.5.2 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/ed569124-2aeb-4b0d-a312-435460892afd/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/3d5199d6-9bb2-4f7b-bd81-bded704da499/");

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

if (version_is_less(version: version, test_version: "1.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
