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
  script_oid("1.3.6.1.4.1.25623.1.0.821255");
  script_version("2022-06-01T13:00:54+0000");
  script_cve_id("CVE-2022-1853", "CVE-2022-1854", "CVE-2022-1855", "CVE-2022-1856",
                "CVE-2022-1857", "CVE-2022-1858", "CVE-2022-1859", "CVE-2022-1860",
                "CVE-2022-1861", "CVE-2022-1862", "CVE-2022-1863", "CVE-2022-1864",
                "CVE-2022-1865", "CVE-2022-1866", "CVE-2022-1867", "CVE-2022-1868",
                "CVE-2022-1869", "CVE-2022-1870", "CVE-2022-1871", "CVE-2022-1872",
                "CVE-2022-1873", "CVE-2022-1874", "CVE-2022-1875", "CVE-2022-1876");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-06-02 06:59:17 +0000 (Thu, 02 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-01 15:36:12 +0530 (Wed, 01 Jun 2022)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop_24-2022-05)-Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple use after free errors in Indexed DB, ANGLE, Messaging, User Education, etc.

  - Insufficient policy enforcement in File System API.

  - Out of bounds read in DevTools.

  - Inappropriate implementation in Extensions.

  - Insufficient validation of untrusted input in Data Transfer.

  - Type Confusion in V8.

  - Multiple insufficient policy enforcement errors in Extensions API, COOP, and Safe Browsing.

  - Inappropriate implementation in PDF.

  - Heap buffer overflow in DevTools.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct out-of-bounds memory access, execute arbitrary code, disclose sensitive
  information and cause a denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 102.0.5005.61
  on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 102.0.5005.61
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/05/stable-channel-update-for-desktop_24.html");
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

if(version_is_less(version:vers, test_version:"102.0.5005.61"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.0.5005.61", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
