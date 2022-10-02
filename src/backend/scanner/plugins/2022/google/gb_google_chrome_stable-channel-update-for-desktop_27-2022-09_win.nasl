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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826553");
  script_version("2022-09-29T10:24:47+0000");
  script_cve_id("CVE-2022-3304", "CVE-2022-3201", "CVE-2022-3305", "CVE-2022-3306",
                "CVE-2022-3307", "CVE-2022-3308", "CVE-2022-3309", "CVE-2022-3310",
                "CVE-2022-3311", "CVE-2022-3312", "CVE-2022-3313", "CVE-2022-3314",
                "CVE-2022-3315", "CVE-2022-3316", "CVE-2022-3317", "CVE-2022-3318");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-09-29 10:24:47 +0000 (Thu, 29 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-28 12:55:52 +0530 (Wed, 28 Sep 2022)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_27-2022-09) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free in CSS.

  - Insufficient validation of untrusted input in Developer Tools.

  - Use after free in Survey.

  - Use after free in Media.

  - Insufficient policy enforcement in Developer Tools.

  - Use after free in Assistant.

  - Insufficient policy enforcement in Custom Tabs.

  - Use after free in Import.

  - Insufficient validation of untrusted input in VPN.

  - Incorrect security UI in Full Screen.

  - Use after free in Logging.

  - Type confusion in Blink.

  - Insufficient validation of untrusted input in Safe Browsing.

  - Insufficient validation of untrusted input in Intents.

  - Use after free in ChromeOS Notifications.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  106.0.5249.61 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  106.0.5249.61 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/09/stable-channel-update-for-desktop_27.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"106.0.5249.61"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"106.0.5249.61", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
