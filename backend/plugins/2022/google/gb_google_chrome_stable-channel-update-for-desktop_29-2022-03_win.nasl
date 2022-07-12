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
  script_oid("1.3.6.1.4.1.25623.1.0.820049");
  script_version("2022-03-31T07:10:52+0000");
  script_cve_id("CVE-2022-1125", "CVE-2022-1127", "CVE-2022-1128", "CVE-2022-1129",
                "CVE-2022-1130", "CVE-2022-1131", "CVE-2022-1132", "CVE-2022-1133",
                "CVE-2022-1134", "CVE-2022-1135", "CVE-2022-1136", "CVE-2022-1137",
                "CVE-2022-1138", "CVE-2022-1139", "CVE-2022-1141", "CVE-2022-1142",
                "CVE-2022-1143", "CVE-2022-1144", "CVE-2022-1145", "CVE-2022-1146");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-31 10:35:16 +0530 (Thu, 31 Mar 2022)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_29-2022-03) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple use after free errors.

  - Multiple heap buffer overflow errors.

  - Type Confusion error in V8.

  - Inappropriate implementation errors.

  - An input validation error in WebOTP.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct denial of service, information disclosure and possibly code execution.");

  script_tag(name:"affected", value:"Google Chrome version prior to 100.0.4896.60
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 100.0.4896.60
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/03/stable-channel-update-for-desktop_29.html");
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

if(version_is_less(version:vers, test_version:"100.0.4896.60"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"100.0.4896.60", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
