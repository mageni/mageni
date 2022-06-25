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
  script_oid("1.3.6.1.4.1.25623.1.0.819980");
  script_version("2022-02-04T08:16:44+0000");
  script_cve_id("CVE-2022-0452", "CVE-2022-0453", "CVE-2022-0454", "CVE-2022-0455",
                "CVE-2022-0456", "CVE-2022-0457", "CVE-2022-0458", "CVE-2022-0459",
                "CVE-2022-0460", "CVE-2022-0461", "CVE-2022-0462", "CVE-2022-0463",
                "CVE-2022-0464", "CVE-2022-0465", "CVE-2022-0466", "CVE-2022-0467",
                "CVE-2022-0468", "CVE-2022-0469", "CVE-2022-0470");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-02-04 11:00:11 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-03 10:56:22 +0530 (Thu, 03 Feb 2022)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2022-02)-MAC OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An use after free error in Safe Browsing.

  - An use after free error in Reader Mode.

  - A heap buffer overflow error in ANGLE.

  - An inappropriate implementation in Full Screen Mode.

  - An use after free error in Web Search.

  - A type confusion error in V8.

  - An use after free error in Thumbnail Tab Strip.

  - An use after free error in Screen Capture.

  - An use after free error in Window Dialog.

  - A policy bypass error in COOP.

  - An inappropriate implementation error in Scroll.

  - An use after free error in Accessibility.

  - An use after free error in Extensions.

  - An inappropriate implementation in Extensions Platform.

  - An inappropriate implementation in Pointer Lock.

  - An use after free error in Payments.

  - An use after free error in Cast.

  - An out of bounds memory access error in V8.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code, disclose sensitive information and
  cause denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 98.0.4758.80
  on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 98.0.4758.80
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/02/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"98.0.4758.80"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"98.0.4758.80", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
