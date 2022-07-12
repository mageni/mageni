# Copyright (C) 2020 Greenbone Networks GmbH
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


CPE = "cpe:/a:adobe:acrobat_reader_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816811");
  script_version("2020-03-20T06:19:59+0000");
  script_cve_id("CVE-2020-3804", "CVE-2020-3806", "CVE-2020-3795", "CVE-2020-3799",
                "CVE-2020-3792", "CVE-2020-3793", "CVE-2020-3801", "CVE-2020-3802",
                "CVE-2020-3805", "CVE-2020-3800", "CVE-2020-3807", "CVE-2020-3797",
                "CVE-2020-3803");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-03-20 13:26:01 +0000 (Fri, 20 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-18 10:10:57 +0530 (Wed, 18 Mar 2020)");
  script_name("Adobe Reader DC (Continuous) Security Updates(apsb20-13)-Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader DC
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to following
  errors,

  - An out-of-bounds read.

  - An out-of-bounds write.

  - A stack-based buffer overflow.

  - An use-after-free.

  - Memory address leak.

  - Buffer overflow.

  - Memory corruption.

  - Insecure library loading (DLL hijacking).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to sensitive information, gain escalated privileges
  and execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Reader DC 2020 (Continuous)
  versions before 2020.006.20042 on Windows.");

  script_tag(name:"solution", value:"Upgrade Adobe Reader DC (Continuous)
  to version 2020.006.20042 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-13.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_cont_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Continuous/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");


if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );

readerVer = infos['version'];
InstallPath = infos['location'];

if(version_in_range(version:readerVer, test_version:"20.0", test_version2:"20.006.20041"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"20.006.20042 (2020.006.20042)", install_path:InstallPath);
  security_message(data:report);
  exit(0);
}
