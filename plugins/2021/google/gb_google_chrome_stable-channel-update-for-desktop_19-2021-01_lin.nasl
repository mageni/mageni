# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817589");
  script_version("2021-01-22T06:41:37+0000");
  script_cve_id("CVE-2021-21117", "CVE-2021-21118", "CVE-2021-21119", "CVE-2021-21120",
                "CVE-2021-21121", "CVE-2021-21122", "CVE-2021-21123", "CVE-2021-21124",
                "CVE-2021-21125", "CVE-2020-16044", "CVE-2021-21126", "CVE-2021-21127",
                "CVE-2021-21128", "CVE-2021-21129", "CVE-2021-21130", "CVE-2021-21131",
                "CVE-2021-21132", "CVE-2021-21133", "CVE-2021-21134", "CVE-2021-21135",
                "CVE-2021-21136", "CVE-2021-21137", "CVE-2021-21138", "CVE-2021-21139",
                "CVE-2021-21140", "CVE-2021-21141");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-01-22 11:28:48 +0000 (Fri, 22 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-20 10:09:03 +0530 (Wed, 20 Jan 2021)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop_19-2021-01)-Linux");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Insufficient policy enforcement in Cryptohome.

  - Insufficient data validation in V8.

  - Use after free in Media.

  - Use after free in WebSQL.

  - Use after free in Omnibox.

  - Use after free in Blink.

  - Insufficient data validation in File System API.

  - Potential user after free in Speech Recognizer.

  - Insufficient policy enforcement in File System API.

  - Use after free in WebRTC.

  - Insufficient policy enforcement in extensions.

  - Heap buffer overflow in Blink.

  - Inappropriate implementation in DevTools.

  - Insufficient policy enforcement in Downloads.

  - Incorrect security UI in Page Info.

  - Inappropriate implementation in Performance API.

  - Insufficient policy enforcement in WebView.

  - Use after free in DevTools.

  - Inappropriate implementation in iframe sandbox.

  - Uninitialized Use in USB.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, gain access to sensitive data, bypass security
  restrictions, and launch denial of service attacks.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 88.0.4324.96 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  88.0.4324.96 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/01/stable-channel-update-for-desktop_19.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"88.0.4324.96"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"88.0.4324.96", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
