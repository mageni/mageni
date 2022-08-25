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
  script_oid("1.3.6.1.4.1.25623.1.0.826415");
  script_version("2022-08-22T10:11:10+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-2852", "CVE-2022-2854", "CVE-2022-2855", "CVE-2022-2857",
                "CVE-2022-2858", "CVE-2022-2853", "CVE-2022-2856", "CVE-2022-2859",
                "CVE-2022-2860", "CVE-2022-2861");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-08-22 10:11:10 +0000 (Mon, 22 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-18 16:35:23 +0530 (Thu, 18 Aug 2022)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_16-2022-08) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free in FedCM.

  - Use after free in SwiftShader.

  - Use after free in ANGLE.

  - Use after free in Blink.

  - Use after free in Sign-In Flow.

  - Heap buffer overflow in Downloads.

  - Insufficient validation of untrusted input in Intents.

  - Use after free in Chrome OS Shell.

  - Insufficient policy enforcement in Cookies.

  - Inappropriate implementation in Extensions API.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, and cause a memory leak on affected
  system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  104.0.5112.101 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  104.0.5112.101 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/08/stable-channel-update-for-desktop_16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"104.0.5112.101"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"104.0.5112.101", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
