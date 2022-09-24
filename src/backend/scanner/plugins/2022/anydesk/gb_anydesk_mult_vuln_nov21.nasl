# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:anydesk:anydesk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126141");
  script_version("2022-09-20T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-20 10:11:40 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-16 06:58:43 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2021-44425", "CVE-2021-44426");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("AnyDesk Multiple Vulnerabilities (Nov 2021) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_anydesk_detect_win.nasl");
  script_mandatory_keys("AnyDesk/Win/Installed");

  script_tag(name:"summary", value:"AnyDesk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2021-44425: The attacker is able to compromise the service listening to the port and
  possibly advance further within the secure corporate network and access sensitive data.

  - CVE-2021-44426: The attacker can persuade a victim to connect to the same remote computer,
  and then plant the malicious file in the victim's filesystem without the victim knowledge.");

  script_tag(name:"affected", value:"AnyDesk version 6.3.x through 6.3.5.");

  script_tag(name:"solution", value:"Update to version 6.3.5 or later.");

  script_xref(name:"URL", value:"https://anydesk.com/en/changelog/windows");
  script_xref(name:"URL", value:"https://argus-sec.com/discovering-tunneling-service-security-flaws-in-anydesk-remote-application/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "6.3.0", test_version2: "6.3.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.3.5", install_path: location );
  security_message( port: 0, data: report );
  exit(0);
}

exit(0);
