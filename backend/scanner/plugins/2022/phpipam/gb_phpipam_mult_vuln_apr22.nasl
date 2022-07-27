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
  script_oid("1.3.6.1.4.1.25623.1.0.124055");
  script_version("2022-04-06T15:45:51+0000");
  script_tag(name:"last_modification", value:"2022-04-06 15:45:51 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-06 17:30:22 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2022-1223", "CVE-2022-1224", "CVE-2022-1225");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpIPAM < 1.4.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ipam_detect.nasl");
  script_mandatory_keys("phpipam/installed");

  script_tag(name:"summary", value:"phpIPAM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-1223: A normal user with the role of User could download or export IP subnets that may contain sensitive
  information related data such as IP address, IP state, MAC, owner, hostname and device via export-subnet.php
endpoint

  - CVE-2022-1224: A normal user with the role of User could view/read the log files via show-logs.php, error_logs.php
  and access_logs.php endpoints

  - CVE-2022-1225: phpIPAM incorrectly assigns a privilege to a particular actor, creating an unintended sphere of
  control for that actor in the Import/Export feature");

  script_tag(name:"affected", value:"phpIPAM prior to version 1.4.6.");

  script_tag(name:"solution", value:"Update to version 1.4.6 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/cd9e1508-5682-427e-a921-14b4f520b85a");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/49b44cfa-d142-4d79-b529-7805507169d2");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/baec4c23-2466-4b13-b3c0-eaf1d000d4ab");

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

if (version_is_less(version: version, test_version: "1.4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
