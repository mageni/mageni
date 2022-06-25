# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.815853");
  script_version("2019-12-03T07:07:39+0000");
  script_cve_id("CVE-2019-13724", "CVE-2019-13723");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-12-03 07:07:39 +0000 (Tue, 03 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-11-20 10:10:32 +0530 (Wed, 20 Nov 2019)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop_18-2019-11)-Mac OS X");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - An use-after-free error in Bluetooth.

  - An out-of-bounds access error in Bluetooth.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to remotely execute code, leak sensitive data or cause denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 78.0.3904.108
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  78.0.3904.108 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/11/stable-channel-update-for-desktop_18.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];
if(version_is_less(version:vers, test_version:"78.0.3904.108"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"78.0.3904.108", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
