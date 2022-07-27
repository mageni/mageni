##############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Acrobat Reader DC (Classic Track) Security Updates(apsb18-34)-Windows
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:adobe:acrobat_reader_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814031");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-12848", "CVE-2018-12849", "CVE-2018-12850", "CVE-2018-12801",
                "CVE-2018-12840", "CVE-2018-12778", "CVE-2018-12775", "CVE-2018-19721",
                "CVE-2018-19723");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-09-20 10:19:20 +0530 (Thu, 20 Sep 2018)");
  script_name("Adobe Acrobat Reader DC (Classic Track) Security Updates(apsb18-34)-Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat Reader
  DC (Classic Track) and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple out-of-bounds read errors.

  - An out-of-bounds write error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to conduct arbitrary code execution in the context of the current
  user and also disclose sensitive information.");

  script_tag(name:"affected", value:"Adobe Acrobat Reader DC (Classic Track)
  2015.006.30448 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat Reader DC (Classic
  Track) version 2015.006.30452 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-29.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Classic/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

## 2015.006.30452 => 15.006.30452
if(version_is_less(version:vers, test_version:"15.006.30452"))
{
  report =  report_fixed_ver(installed_version:vers, fixed_version:"2015.006.30452", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
