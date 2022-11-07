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

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127227");
  script_version("2022-10-25T09:12:58+0000");
  script_tag(name:"last_modification", value:"2022-10-25 09:12:58 +0000 (Tue, 25 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-24 10:11:43 +0000 (Mon, 24 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

  script_cve_id("CVE-2022-28291");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Tenable Nessus <= 10.4.0 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");

  script_tag(name:"summary", value:"Tenable Nessus is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can retrieve stored credentials in Nessus Policies
  in cleartext from the 'nessusd' process.");

  script_tag(name:"affected", value:"Tenable Nessus 10.4.0 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 24th October, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://cybersecurityworks.com/blog/zero-days/csw-expert-discovers-a-zero-day-vulnerability-in-tenables-nessus-scanner.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_less_equal(version:vers, test_version:"10.4.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
