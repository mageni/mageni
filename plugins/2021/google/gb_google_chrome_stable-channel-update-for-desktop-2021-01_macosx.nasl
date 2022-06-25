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
  script_oid("1.3.6.1.4.1.25623.1.0.817562");
  script_version("2021-01-12T06:08:58+0000");
  script_cve_id("CVE-2021-21106", "CVE-2021-21107", "CVE-2021-21108", "CVE-2021-21109",
                "CVE-2021-21110", "CVE-2021-21111", "CVE-2021-21112", "CVE-2021-21113",
                "CVE-2020-16043", "CVE-2021-21114", "CVE-2020-15995", "CVE-2021-21115",
                "CVE-2021-21116");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-01-12 11:05:42 +0000 (Tue, 12 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-07 17:48:08 +0530 (Thu, 07 Jan 2021)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2021-01)-MAC OS X");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Use after free in autofill.

  - Use after free in drag and drop.

  - Use after free in media.

  - Use after free in payments.

  - Use after free in safe browsing.

  - Insufficient policy enforcement in WebUI.

  - Use after free in Blink.

  - Heap buffer overflow in Skia.

  - Insufficient data validation in networking.

  - Use after free in audio.

  - Out of bounds write in V8.

  - Heap buffer overflow in audio.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, gain access to sensitive data, bypass security
  restrictions, and launch denial of service attacks.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 87.0.4280.141 on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  87.0.4280.141 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/01/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"87.0.4280.141"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"87.0.4280.141", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
