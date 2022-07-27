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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818545");
  script_version("2021-09-24T05:06:20+0000");
  script_cve_id("CVE-2021-35982", "CVE-2021-39836", "CVE-2021-39837", "CVE-2021-39838",
                "CVE-2021-39839", "CVE-2021-39840", "CVE-2021-39841", "CVE-2021-39842",
                "CVE-2021-39843", "CVE-2021-39844", "CVE-2021-39845", "CVE-2021-39846",
                "CVE-2021-39849", "CVE-2021-39850", "CVE-2021-39851", "CVE-2021-39852",
                "CVE-2021-39853", "CVE-2021-39854", "CVE-2021-39855", "CVE-2021-39856",
                "CVE-2021-39857", "CVE-2021-39858", "CVE-2021-39859", "CVE-2021-39860",
                "CVE-2021-39861", "CVE-2021-39863");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-09-24 11:43:38 +0000 (Fri, 24 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-17 08:30:24 +0530 (Fri, 17 Sep 2021)");
  script_name("Adobe Acrobat 2017 Security Update (APSB21-55) - Mac OS X");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe September update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use-after-free errors.

  - Multiple out-of-bounds read errors.

  - An out-of-bounds write error.

  - A type confusion error.

  - Multiple buffer overflow errors.

  - Multiple null pointer dereference errors.

  - An input validation error.

  - An arbitrary file system read error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, cause denial of service, read arbitrary files and
  disclose sensitive information on vulnerable system.");

  script_tag(name:"affected", value:"Adobe Acrobat 2017 version prior to
  2017.011.30202 on Mac OS X.");

  script_tag(name:"solution", value:"Update Adobe Acrobat 2017 to version
  2017.011.30202 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-55.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.011.30199"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.011.30202(2017.011.30202)", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
