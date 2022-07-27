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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817354");
  script_version("2020-08-14T06:59:33+0000");
  script_cve_id("CVE-2020-9693", "CVE-2020-9694", "CVE-2020-9696", "CVE-2020-9697",
                "CVE-2020-9698", "CVE-2020-9699", "CVE-2020-9700", "CVE-2020-9701",
                "CVE-2020-9702", "CVE-2020-9703", "CVE-2020-9704", "CVE-2020-9705",
                "CVE-2020-9706", "CVE-2020-9707", "CVE-2020-9710", "CVE-2020-9712",
                "CVE-2020-9714", "CVE-2020-9715", "CVE-2020-9716", "CVE-2020-9717",
                "CVE-2020-9718", "CVE-2020-9719", "CVE-2020-9720", "CVE-2020-9721",
                "CVE-2020-9722", "CVE-2020-9723");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-08-14 09:58:14 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-12 08:49:56 +0530 (Wed, 12 Aug 2020)");
  script_name("Adobe Reader 2017 Security Updates(apsb20-48)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader 2017
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to following
  errors,

  - Multiple Use-after-free errors.

  - Multiple Buffer errors.

  - Multiple Out-of-bounds write.

  - Multiple Out-of-bounds read.

  - Multiple Stack exhaustion errors.

  - Multiple Security bypass.

  - Multiple memory leak errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to sensitive information, gain privilege escalation,
  bypass security restrictions, cause a denial-of-service condition and execute
  arbitrary code.");

  script_tag(name:"affected", value:"Adobe Reader DC 2015 (Classic) prior
  to version 2015.006.30527 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader DC 2015 (Classic) to
  version 2015.006.30527 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-48.html");
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

if(version_in_range(version:readerVer, test_version:"17.0", test_version2:"17.011.30174"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"17.011.30175(2017.011.30175)", install_path:InstallPath);
  security_message(data:report);
  exit(0);
}
exit(99);
