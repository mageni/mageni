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

CPE = "cpe:/a:adobe:lightroom_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826486");
  script_version("2022-09-29T10:24:47+0000");
  script_cve_id("CVE-2021-40776");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-09-29 10:24:47 +0000 (Thu, 29 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-17 22:15:00 +0000 (Wed, 17 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-09-27 21:02:01 +0530 (Tue, 27 Sep 2022)");
  script_name("Adobe Lightroom Classic Privilege escalation Vulnerability (APSB21-97) - Windows");

  script_tag(name:"summary", value:"Adobe Lightroom Classic is privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Creation of Temporary
  File in Directory with Incorrect Permissions.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to escalate privileges on victim's system.");

  script_tag(name:"affected", value:"Adobe Lightroom Classic 10.3 and earlier
  versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Lightroom Classic 10.4 or
  11.0 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/lightroom/apsb21-97.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_lightroom_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/Lightroom/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:vers, test_version:"10.3"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.4 or 11.0 or later", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
