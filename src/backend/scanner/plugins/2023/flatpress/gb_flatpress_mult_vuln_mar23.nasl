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

CPE = "cpe:/a:flatpress:flatpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126370");
  script_version("2023-03-07T10:09:08+0000");
  script_tag(name:"last_modification", value:"2023-03-07 10:09:08 +0000 (Tue, 07 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-02 10:10:47 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:C");

  script_cve_id("CVE-2023-0947", "CVE-2023-1103", "CVE-2023-1104", "CVE-2023-1105",
                "CVE-2023-1106", "CVE-2023-1107", "CVE-2023-1146", "CVE-2023-1147",
                "CVE-2023-1148");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FlatPress < 1.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_flatpress_http_detect.nasl");
  script_mandatory_keys("flatpress/detected");

  script_tag(name:"summary", value:"FlatPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-0947: Path traversal in flatpressblog/flatpress

  - CVE-2023-1103: When user upload a file with .xml extension and access this file, server
  will response with Content-type: image/svg+xml lead to processing XML as HTML file.

  - CVE-2023-1104: When user upload a file with .pages extension and access this file, server
  will response with Content-type: application/octet-stream lead to processing .pages as HTML file.

  - CVE-2023-1105: External control of file name or path in flatpressblog/flatpress.

  - CVE-2023-1106: Unsanitized input returned in response is conducive to XSS exploitation in
  flatpressblog/flatpress

  - CVE-2023-1107: Stored XSS in multiple menus in flatpressblog/flatpress

  - CVE-2023-1146: Stored XSS via blog author parameter on admin.php?p=config in
  flatpressblog/flatpress

  - CVE-2023-1147: Stored XSS through post comment body in flatpressblog/flatpress

  - CVE-2023-1148: Stored XSS via title, subtitle, footer and post title and content in
  flatpressblog/flatpress.");

  script_tag(name:"affected", value:"FlatPress prior to version 1.3.");

  script_tag(name:"solution", value:"Update to version 1.3 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/7379d702-72ff-4a5d-bc68-007290015496/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/4c5a8af6-3078-4180-bb30-33b57a5540e6/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/a4909b4e-ab3c-41d6-b0d8-1c6e933bf758/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/4089a63f-cffd-42f3-b8d8-e80b6bd9c80f/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/1288ec00-f69d-4b84-abce-efc9a97941a0");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/4b880868-bd28-4fd0-af56-7686e55d3762");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/d6d1e1e2-2f67-4d28-aa84-b30fb1d2e737/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/187f5353-f866-4d26-a5ba-fca378520020/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/f0cc2c4b-fdf9-483b-9a83-4e0dfeb4dac7");

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

if (version_is_less(version: version, test_version: "1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

