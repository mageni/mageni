###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Acrobat DC Information Disclosure Vulnerability(apsb18-40)-Windows
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:adobe:acrobat_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814188");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-15979");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-15 12:20:16 +0530 (Thu, 15 Nov 2018)");
  script_name("Adobe Acrobat DC Information Disclosure Vulnerability(apsb18-40)-Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat DC
  and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in handing
  the feature of Portable Document Files (PDFs).That leaks NT LAN Manager (NTLM)
  credentials.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to an inadvertent leak of the users hashed NTLM password.");

  script_tag(name:"affected", value:"Adobe Acrobat DC version 2019.x before 2019.008.20081 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat DC version
  2019.008.20081 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-40.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_cont_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Continuous/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
readerVer = infos['version'];
InstallPath = infos['location'];

if(version_in_range(version:readerVer, test_version:"2019.0", test_version2:"2019.008.20080"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"2019.008.20081", install_path:InstallPath);
  security_message(data:report);
  exit(0);
}
exit(99);
