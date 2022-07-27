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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:acrobat_reader_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814789");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2019-7061", "CVE-2019-7109", "CVE-2019-7110", "CVE-2019-7114",
                "CVE-2019-7115", "CVE-2019-7116", "CVE-2019-7121", "CVE-2019-7122",
                "CVE-2019-7123", "CVE-2019-7127", "CVE-2019-7111", "CVE-2019-7118",
                "CVE-2019-7119", "CVE-2019-7120", "CVE-2019-7124", "CVE-2019-7117",
                "CVE-2019-7128", "CVE-2019-7088", "CVE-2019-7112", "CVE-2019-7113",
                "CVE-2019-7125");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-04-11 11:09:50 +0530 (Thu, 11 Apr 2019)");
  script_name("Adobe Acrobat Reader DC (Classic Track) Security Updates(apsb19-17)-Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat
  Reader DC Classic 2015 and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple out-of-bounds read errors.

  - Multiple out-of-bounds write errors.

  - Type confusionerrors.

  - Use After Free errors.

  - Heap Overflow errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to sensitive information and run arbitrary code in context of
  current user.");

  script_tag(name:"affected", value:"Adobe Acrobat Reader DC Classic 2015 version
  2015.x before 2015.006.30493 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat DC Classic 2015 version
  2015.006.30493 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-17.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Classic/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
readerVer = infos['version'];
InstallPath = infos['location'];

## 2015.006.30493 == 15.006.30493
if(version_is_less(version:readerVer, test_version:"15.006.30493"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"15.006.30493", install_path:InstallPath);
  security_message(data:report);
  exit(0);
}
exit(99);
