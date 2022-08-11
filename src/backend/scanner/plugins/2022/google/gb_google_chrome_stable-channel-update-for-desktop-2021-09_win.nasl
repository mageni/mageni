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
  script_oid("1.3.6.1.4.1.25623.1.0.821214");
  script_version("2022-05-10T14:09:17+0000");
  script_cve_id("CVE-2021-30625", "CVE-2021-30626", "CVE-2021-30627", "CVE-2021-30628",
                "CVE-2021-30629", "CVE-2021-30630", "CVE-2021-30632", "CVE-2021-30633");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-11 10:22:31 +0000 (Wed, 11 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-12 23:16:00 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"creation_date", value:"2022-05-09 10:52:42 +0530 (Mon, 09 May 2022)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop-2021-09) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple use after free errors.

  - An inappropriate implementation in Blink.

  - Type Confusion in Blink layout.

  - Out of bounds write in V8.

  - Out of bounds memory access in ANGLE.

  - Stack buffer overflow in ANGLE.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct out-of-bounds memory access, execute arbitrary code, disclose sensitive
  information and cause denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 93.0.4577.82
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 93.0.4577.82
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/09/stable-channel-update-for-desktop.html");
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

if(version_is_less(version:vers, test_version:"93.0.4577.82"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"93.0.4577.82", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
