# Copyright (C) 2020 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817420");
  script_version("2020-08-13T02:02:03+0000");
  script_cve_id("CVE-2020-6542", "CVE-2020-6543", "CVE-2020-6544", "CVE-2020-6545",
                "CVE-2020-6546", "CVE-2020-6547", "CVE-2020-6548", "CVE-2020-6549",
                "CVE-2020-6550", "CVE-2020-6551", "CVE-2020-6552", "CVE-2020-6553",
                "CVE-2020-6554", "CVE-2020-6555");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-08-13 10:32:48 +0000 (Thu, 13 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-12 14:03:19 +0530 (Wed, 12 Aug 2020)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2020-08)-Windows");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - Use after free in ANGLE, task scheduling, media, audio, IndexedDB, WebXR, Blink, offline mode, extensions.

  - Inappropriate implementation in installer.

  - Incorrect security UI in media.

  - Heap buffer overflow in Skia.

  - Out of bounds read in WebGL.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  execute arbitrary code, disclose sensitive information and cause denial of service
  condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 84.0.4147.125 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 84.0.4147.125 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/08/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"84.0.4147.125"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"84.0.4147.125", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
