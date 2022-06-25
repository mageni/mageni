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
  script_oid("1.3.6.1.4.1.25623.1.0.817284");
  script_version("2020-09-02T06:38:34+0000");
  script_cve_id("CVE-2020-6492");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-09-02 10:05:23 +0000 (Wed, 02 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-02 11:51:49 +0530 (Wed, 02 Sep 2020)");
  script_name("Google Chrome WebGL Code Execution Vulnerability(Aug-2020)-Windows");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaws exists due to WebGL component
  fails to correctly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  execute arbitrary code in the context of the browser.");

  script_tag(name:"affected", value:"Google Chrome version prior to 85.0.4149.0 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 85.0.4149.0 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.bleepingcomputer.com/news/security/google-chrome-85-fixes-webgl-code-execution-vulnerability/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"85.0.4149.0"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"85.0.4149.0", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
