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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818839");
  script_version("2021-10-28T07:17:35+0000");
  script_cve_id("CVE-2021-37981", "CVE-2021-37982", "CVE-2021-37983", "CVE-2021-37984",
                "CVE-2021-37985", "CVE-2021-37986", "CVE-2021-37987", "CVE-2021-37988",
                "CVE-2021-37989", "CVE-2021-37990", "CVE-2021-37991", "CVE-2021-37992",
                "CVE-2021-37993", "CVE-2021-37996", "CVE-2021-37994", "CVE-2021-37995");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-28 07:17:35 +0000 (Thu, 28 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-25 16:22:33 +0530 (Mon, 25 Oct 2021)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_19-2021-10)-Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Multiple use after free errors.

  - Multiple heap buffer overflow errors.

  - An inappropriate implementation in Blink, WebView, iFrame Sandbox and WebApp Installer.

  - An out of bounds read error in WebAudio.

  - Race in V8.

  - An insufficient validation of untrusted input in Downloads.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, gain access to sensitive data, bypass security
  restrictions, and launch denial of service attacks.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 95.0.4638.54 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 95.0.4638.54 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/10/stable-channel-update-for-desktop_19.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
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

if(version_is_less(version:vers, test_version:"95.0.4638.54"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"95.0.4638.54", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
