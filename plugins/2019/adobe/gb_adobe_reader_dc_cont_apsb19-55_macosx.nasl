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

CPE = "cpe:/a:adobe:acrobat_reader_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815692");
  script_version("2019-12-13T12:11:15+0000");
  script_cve_id("CVE-2019-16449", "CVE-2019-16456", "CVE-2019-16457", "CVE-2019-16458",
                "CVE-2019-16461", "CVE-2019-16465", "CVE-2019-16450", "CVE-2019-16454",
                "CVE-2019-16445", "CVE-2019-16448", "CVE-2019-16452", "CVE-2019-16459",
                "CVE-2019-16464", "CVE-2019-16451", "CVE-2019-16462", "CVE-2019-16446",
                "CVE-2019-16455", "CVE-2019-16460", "CVE-2019-16463", "CVE-2019-16444",
                "CVE-2019-16453");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-12-13 12:11:15 +0000 (Fri, 13 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-12 12:24:49 +0530 (Thu, 12 Dec 2019)");
  script_name("Adobe Reader DC (Continuous) Security Updates(apsb19-55)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader DC
  (Continuous) and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to following
  errors,

  - An out-of-bounds read.

  - An out-of-bounds write.

  - A use after free.

  - A heap overflow.

  - A buffer error.

  - Untrusted Pointer Dereference.

  - Binary Planting (default folder privilege escalation).

  - A Security Bypass.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain escalated privileges, get access to potentially sensitive
  information and execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Reader DC 2019 (Continuous) prior
  to version 2019.021.20058 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader DC 2019 (Continuous)
  to version 2019.021.20058 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-55.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_cont_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Continuous/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
readerVer = infos['version'];
InstallPath = infos['location'];

## 2019.021.20057 == 19.021.20057
if(version_in_range(version:readerVer, test_version:"19.0", test_version2:"19.021.20057"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"19.021.20058 (2019.021.20058)", install_path:InstallPath);
  security_message(data:report);
  exit(0);
}
exit(99);
