###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Excel Remote Code Execution Vulnerabilities (2293211)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902264");
  script_version("2019-05-03T08:55:39+0000");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-10-13 17:10:12 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-3230", "CVE-2010-3231", "CVE-2010-3232", "CVE-2010-3233",
                "CVE-2010-3234", "CVE-2010-3235", "CVE-2010-3236", "CVE-2010-3237",
                "CVE-2010-3238", "CVE-2010-3239", "CVE-2010-3240", "CVE-2010-3241",
                "CVE-2010-3242");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office Excel Remote Code Execution Vulnerabilities (2293211)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a malicious Excel file.");

  script_tag(name:"affected", value:"Microsoft Excel Viewer Service Pack 2

  Microsoft Office Excel 2002 Service Pack 3

  Microsoft Office Excel 2003 Service Pack 3

  Microsoft Office Excel 2007 Service Pack 2

  Microsoft Office Compatibility Pack for Word,

  Excel, and PowerPoint 2007 File Formats Service Pack 2");

  script_tag(name:"insight", value:"The flaws are due to:

  - An integer overflow error when processing record information

  - A memory corruption error when processing malformed records

  - A memory corruption error when processing malformed Lotus 1-2-3 workbook
    (.wk3) file.

  - A memory corruption error when processing malformed formula information

  - A memory corruption error when processing malformed formula BIFF records

  - An out-of-bounds array when processing malformed records

  - An invalid pointer when processing malformed Merge Cell records.

  - A memory corruption error when processing negative future functions

  - An out-of-boundary access when processing malformed records

  - An array indexing error when processing malformed Real Time Data records

  - An out-of-bounds memory write when processing malformed data

  - A memory corruption error when processing malformed Ghost records");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-080.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2345017");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2344893");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2345035");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2345088");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2344875");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2627");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-080.mspx");

  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer && excelVer =~ "^1[012]\.0")
{
  if(version_in_range(version:excelVer, test_version:"10.0", test_version2:"10.0.6865") ||
     version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8327") ||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6545.4999"))
  {
    report = report_fixed_ver(installed_version:excelVer, vulnerable_range:"10.0 - 10.0.6865, 11.0 - 11.0.8327, 12.0 - 12.0.6545.4999");
    security_message(port:0, data:report);
    exit(0);
  }
}

cmpPckVer = get_kb_item("SMB/Office/ComptPack/Version");
if(cmpPckVer && cmpPckVer =~ "^12\.0")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer && xlcnvVer =~ "^12\.0")
  {
    if(version_in_range(version:xlcnvVer, test_version:"12.0", test_version2:"12.0.6545.4999"))
    {
      report = report_fixed_ver(installed_version:cmpPckVer, vulnerable_range:"12.0 - 12.0.6545.4999");
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

excelVer = get_kb_item("SMB/Office/XLView/Version");
if(excelVer && excelVer =~ "^12\.0")
{
  if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6545.4999")){
    report = report_fixed_ver(installed_version:excelVer, vulnerable_range:"12.0 - 12.0.6545.4999");
    security_message(port:0, data:report);
  }
}
