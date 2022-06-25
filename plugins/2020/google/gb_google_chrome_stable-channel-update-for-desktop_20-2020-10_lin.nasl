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
  script_oid("1.3.6.1.4.1.25623.1.0.817519");
  script_version("2020-10-22T06:28:27+0000");
  script_cve_id("CVE-2020-16000", "CVE-2020-16001", "CVE-2020-16002", "CVE-2020-15999",
                "CVE-2020-16003");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-10-22 10:10:52 +0000 (Thu, 22 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-21 10:23:51 +0530 (Wed, 21 Oct 2020)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop_20-2020-10)-Linux");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Inappropriate implementation in Blink.

  - Use after free in media.

  - Use after free in PDFium.

  - Heap buffer overflow in Freetype.

  - Use after free in printing.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code or crash affected system.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 86.0.4240.111 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  86.0.4240.111 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/10/stable-channel-update-for-desktop_20.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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

if(version_is_less(version:chr_ver, test_version:"86.0.4240.111"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"86.0.4240.111", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
