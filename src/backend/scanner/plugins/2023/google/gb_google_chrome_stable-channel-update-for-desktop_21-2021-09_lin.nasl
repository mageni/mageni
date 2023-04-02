# Copyright (C) 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
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
  script_oid("1.3.6.1.4.1.25623.1.0.826944");
  script_version("2023-03-28T10:09:39+0000");
  script_cve_id("CVE-2021-37956", "CVE-2021-37957", "CVE-2021-37958", "CVE-2021-37959",
                "CVE-2021-37961", "CVE-2021-37962", "CVE-2021-37963", "CVE-2021-37964",
                "CVE-2021-37965", "CVE-2021-37966", "CVE-2021-37967", "CVE-2021-37968",
                "CVE-2021-37969", "CVE-2021-37970", "CVE-2021-37971", "CVE-2021-37972");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-12 22:39:00 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"creation_date", value:"2023-03-23 15:42:38 +0530 (Thu, 23 Mar 2023)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_21-2021-09) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free in WebGPU.

  - Inappropriate implementation in Navigation.

  - Use after free in Task Manager.

  - Use after free in Tab Strip.

  - Use after free in Performance Manager.

  - Side-channel information leakage in DevTools.

  - Inappropriate implementation in ChromeOS Networking.

  - Inappropriate implementation in Background Fetch API.

  - Inappropriate implementation in Compositing.

  - Inappropriate implementation in Google Updater.

  - Use after free in File System API.

  - Incorrect security UI in Web Browser UI.

  - Out of bounds read in libjpeg-turbo.

  - Use after free in Offline use.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  94.0.4606.54 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  94.0.4606.54 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/09/stable-channel-update-for-desktop_21.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"94.0.4606.54"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"94.0.4606.54", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
