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

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126304");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-23 12:50:47 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2023-0101");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 8.15.8, 10.0.x < 10.4.2 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");

  script_tag(name:"summary", value:"Tenable Nessus is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An authenticated attacker could potentially execute a specially
  crafted file to obtain root or NT AUTHORITY / SYSTEM privileges on the Nessus host.");

  script_tag(name:"affected", value:"Tenable Nessus versions prior to 8.15.8 and 10.0.x prior to 10.4.2.");

  script_tag(name:"solution", value:"Update to version 8.15.8, 10.4.2 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-01");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-02");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "8.15.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.15.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
