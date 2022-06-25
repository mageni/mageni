###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Excel 2016 Multiple Vulnerabilities (KB4461542)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814526");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-8597", "CVE-2018-8598", "CVE-2018-8627", "CVE-2018-8636");
  script_bugtraq_id(106100, 106102, 106120, 106101);
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"creation_date", value:"2018-12-12 12:24:05 +0530 (Wed, 12 Dec 2018)");
  script_name("Microsoft Excel 2016 Multiple Vulnerabilities (KB4461542)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4461542");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists,

  - In Microsoft Excel software when the software fails to properly handle objects
    in memory.

  - when Microsoft Excel improperly discloses the contents of its memory.

  - when Microsoft Excel software reads out of bound memory due to an
    uninitialized variable, which could disclose the contents of memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to
  run arbitrary code in the context of the current user, use the information to
  compromise the user's computer or data and view out of bound memory.");

  script_tag(name:"affected", value:"Microsoft Excel 2010 Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4461542");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(!excelVer){
  exit(0);
}

excelPath = get_kb_item("SMB/Office/Excel/Install/Path");
if(!excelPath){
  excelPath = "Unable to fetch the install path";
}

if(excelVer =~ "^16\." && version_is_less(version:excelVer, test_version:"16.0.4783.1000"))
{
  report = report_fixed_ver(file_checked:excelPath + "Excel.exe",
                            file_version:excelVer, vulnerable_range:"16.0 - 16.0.4783.0999");
  security_message(data:report);
  exit(0);
}
exit(99);
