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
  script_oid("1.3.6.1.4.1.25623.1.0.820082");
  script_version("2022-04-20T08:12:51+0000");
  script_cve_id("CVE-2022-1364");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-20 10:08:00 +0000 (Wed, 20 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-19 11:47:47 +0530 (Tue, 19 Apr 2022)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_14-2022-04) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to type confusion
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a type confusion error in V8.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct privilege escalation.");

  script_tag(name:"affected", value:"Google Chrome version prior to 100.0.4896.127
  on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 100.0.4896.127
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/04/stable-channel-update-for-desktop_14.html");
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

if(version_is_less(version:vers, test_version:"100.0.4896.127"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"100.0.4896.127", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
