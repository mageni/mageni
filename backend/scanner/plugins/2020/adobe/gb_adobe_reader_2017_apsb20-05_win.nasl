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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816568");
  script_version("2020-02-13T13:02:04+0000");
  script_cve_id("CVE-2020-3744", "CVE-2020-3747", "CVE-2020-3755", "CVE-2020-3742",
                "CVE-2020-3752", "CVE-2020-3754", "CVE-2020-3743", "CVE-2020-3745",
                "CVE-2020-3746", "CVE-2020-3748", "CVE-2020-3749", "CVE-2020-3750",
                "CVE-2020-3751", "CVE-2020-3753", "CVE-2020-3756", "CVE-2020-3762",
                "CVE-2020-3763");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-02-13 13:02:04 +0000 (Thu, 13 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-13 11:18:45 +0530 (Thu, 13 Feb 2020)");
  script_name("Adobe Reader 2017 Security Updates(apsb20-05)-Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader 2017
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to following
  errors,

  - An out-of-bounds read.

  - Heap overflow.

  - Buffer Error.

  - Use After Free.

  - Stack exhaustion.

  - Privilege Escalation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to sensitive data, execute arbitrary code, gain
  privileged access and memory leak condition.");

  script_tag(name:"affected", value:"Adobe Reader 2017 prior to version
  2017.011.30158 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader 2017 version
  2017.011.30158 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-05.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
readerVer = infos['version'];
InstallPath = infos['location'];

if(version_in_range(version:readerVer, test_version:"17.0", test_version2:"17.011.30157"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"17.011.30157(2017.011.30158)", install_path:InstallPath);
  security_message(data:report);
  exit(0);
}
exit(99);
