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


CPE = "cpe:/a:adobe:acrobat_reader_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817123");
  script_version("2020-05-15T04:25:55+0000");
  script_cve_id("CVE-2020-9610", "CVE-2020-9612", "CVE-2020-9615", "CVE-2020-9597",
                "CVE-2020-9594", "CVE-2020-9614", "CVE-2020-9613", "CVE-2020-9596",
                "CVE-2020-9592", "CVE-2020-9611", "CVE-2020-9609", "CVE-2020-9608",
                "CVE-2020-9603", "CVE-2020-9602", "CVE-2020-9601", "CVE-2020-9600",
                "CVE-2020-9599", "CVE-2020-9605", "CVE-2020-9604", "CVE-2020-9607",
                "CVE-2020-9606", "CVE-2020-9598", "CVE-2020-9595", "CVE-2020-9593");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-05-15 10:12:07 +0000 (Fri, 15 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-14 11:57:19 +0530 (Thu, 14 May 2020)");
  script_name("Adobe Reader DC Security Updates(apsb20-24)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader DC
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to following
  errors,

  - A null pointer error.

  - Heap overflow.

  - Race condition.

  - Out-of-bounds write.

  - Security bypass.

  - Stack exhaustion.

  - Out-of-bounds read.

  - Buffer error.

  - Use-after-free.

  - Invalid memory access.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct a denial-of-service condition, execute arbitrary code,
  bypass security features and gain access to sensitive information");

  script_tag(name:"affected", value:"Adobe Reader DC version 2020 (Continuous)
  versions before 2020.009.20063 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader DC (Continuous)
  to version 2020.009.20063 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-24.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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

if(version_in_range(version:readerVer, test_version:"20.0", test_version2:"20.009.20062"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"20.009.20063(2020.009.20063)", install_path:InstallPath);
  security_message(data:report);
  exit(0);
}
