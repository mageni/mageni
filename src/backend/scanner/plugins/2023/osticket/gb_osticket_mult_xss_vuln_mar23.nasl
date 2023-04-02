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

CPE = "cpe:/a:osticket:osticket";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126384");
  script_version("2023-03-16T10:09:04+0000");
  script_tag(name:"last_modification", value:"2023-03-16 10:09:04 +0000 (Thu, 16 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-14 09:30:46 +0000 (Tue, 14 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 20:37:00 +0000 (Mon, 18 Apr 2022)");

  script_cve_id("CVE-2022-1315", "CVE-2022-1316", "CVE-2022-1317", "CVE-2022-1318",
                "CVE-2022-1319", "CVE-2022-1320");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("osTicket < 1.16.6, 1.17.x < 1.17.3 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("osticket_http_detect.nasl");
  script_mandatory_keys("osticket/detected");

  script_tag(name:"summary", value:"osTicket is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-1315: Reflected XSS in Advanced Ticket Search in osticket/osticket

  - CVE-2022-1316: Stored XSS in Email in osticket/osticket

  - CVE-2022-1317: Reflected XSS in Organizations Search in osticket/osticket

  - CVE-2022-1318: Multiple XSS in Queue Condition in osticket/osticket

  - CVE-2022-1319: Stored XSS in Roles in osticket/osticket

  - CVE-2022-1320: Stored XSS leading unauthenticated user to upload malicious html/js file.");

  script_tag(name:"affected", value:"osTicket prior to version 1.16.6 and version 1.17.x prior to
  1.17.3.");

  script_tag(name:"solution", value:"Update to version 1.16.6, 1.17.3 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/70a7fd8c-7e6f-4a43-9f8c-163b8967b16e/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/c6353bab-c382-47f6-937b-56d253f2e8d3/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/c3e27af2-358b-490b-9baf-e451663e4e5f/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/e58b38e0-4897-4bb0-84e8-a7ad8efab338/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/a822067a-d90d-4c3e-b9ef-9b2a5c2bc97f/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/c2bb34ac-452d-4624-a1b9-c5b54f52f0cd/");
  script_xref(name:"URL", value:"https://osticket.com/osticket-v1-16-6-v1-17-3-available/");

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

if (version_is_less(version: version, test_version: "1.16.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.16.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.17", test_version_up: "1.17.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.17.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
