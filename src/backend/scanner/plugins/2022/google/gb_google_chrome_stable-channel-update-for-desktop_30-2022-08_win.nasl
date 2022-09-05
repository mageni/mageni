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
  script_oid("1.3.6.1.4.1.25623.1.0.826430");
  script_version("2022-09-02T12:27:39+0000");
  script_cve_id("CVE-2022-3038", "CVE-2022-3039", "CVE-2022-3040", "CVE-2022-3041",
                "CVE-2022-3042", "CVE-2022-3043", "CVE-2022-3044", "CVE-2022-3045",
                "CVE-2022-3046", "CVE-2022-3071", "CVE-2022-3047", "CVE-2022-3048",
                "CVE-2022-3049", "CVE-2022-3050", "CVE-2022-3051", "CVE-2022-3052",
                "CVE-2022-3053", "CVE-2022-3054", "CVE-2022-3055", "CVE-2022-3056",
                "CVE-2022-3057", "CVE-2022-3058");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-09-02 12:27:39 +0000 (Fri, 02 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-01 17:11:09 +0530 (Thu, 01 Sep 2022)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_30-2022-08) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free in Network Service.

  - Use after free in WebSQL.

  - Use after free in Layout.

  - Use after free in PhoneHub.

  - Heap buffer overflow in Screen Capture.

  - Inappropriate implementation in Site Isolation.

  - Insufficient validation of untrusted input in V8.

  - Use after free in Browser Tag.

  - Use after free in Tab Strip.

  - Insufficient policy enforcement in Extensions API.

  - Inappropriate implementation in Chrome OS lockscreen.

  - Use after free in SplitScreen.

  - Heap buffer overflow in WebUI.

  - Heap buffer overflow in Exosphere.

  - Heap buffer overflow in Window Manager.

  - Inappropriate implementation in Pointer Lock.

  - Insufficient policy enforcement in DevTools.

  - Use after free in Passwords.

  - Insufficient policy enforcement in Content Security Policy.

  - Inappropriate implementation in iframe Sandbox.

  - Use after free in Sign-In Flow.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, conduct spoofing and cause memory leak
  on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  105.0.5195.52 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  105.0.5195.52 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/08/stable-channel-update-for-desktop_30.html");
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

if(version_is_less(version:vers, test_version:"105.0.5195.52"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"105.0.5195.52/53/54", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
