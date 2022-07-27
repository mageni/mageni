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

CPE = "cpe:/a:apple:xcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817898");
  script_version("2021-01-29T03:26:34+0000");
  script_cve_id("CVE-2020-5260");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-01-29 11:05:10 +0000 (Fri, 29 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-28 12:48:59 +0530 (Thu, 28 Jan 2021)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple Xcode Path Traversal Vulnerability (HT212153)");

  script_tag(name:"summary", value:"This host is installed with Apple Xcode
  and is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a path handling error
  related to improper input validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to access arbitrary files on the host device while running an app
  that uses on-demand resources with Xcode.");

  script_tag(name:"affected", value:"Apple Xcode prior to version 12.4");

  script_tag(name:"solution", value:"Upgrade to Apple Xcode 12.4 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212153");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl", "gb_xcode_detect_macosx.nasl");
  script_mandatory_keys("ssh/login/osx_version", "Xcode/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || version_is_less(version:osVer, test_version:"10.15.4")){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)){
  exit(0);
}

xcVer = infos['version'];
xcpath = infos['location'];

if(version_is_less(version:xcVer, test_version:"12.4"))
{
  report = report_fixed_ver(installed_version:xcVer, fixed_version:"12.4", install_path:xcpath);
  security_message(data:report);
  exit(0);
}
exit(0);
