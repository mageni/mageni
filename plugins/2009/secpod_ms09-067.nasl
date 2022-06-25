###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Excel Multiple Vulnerabilities (972652)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900887");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-11-11 19:07:38 +0100 (Wed, 11 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3127", "CVE-2009-3128", "CVE-2009-3129", "CVE-2009-3130",
                "CVE-2009-3131", "CVE-2009-3132", "CVE-2009-3133", "CVE-2009-3134");
  script_bugtraq_id(36943, 36944, 36945, 36946, 36908, 36909, 36911, 36912);
  script_name("Microsoft Office Excel Multiple Vulnerabilities (972652)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Prdts/Installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37299/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/972652");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS09-067");

  script_tag(name:"impact", value:"Successful exploitation could execute arbitrary code on the remote system
  and corrupt memory, buffer overflow via a specially crafted Excel file.");

  script_tag(name:"affected", value:"Microsoft Excel Viewer 2003/2007

  Microsoft Office Excel 2002/2003/2007

  Microsoft Office Compatibility Pack for Word, Excel, PowerPoint 2007 File Formats SP 1/2");

  script_tag(name:"insight", value:"- An error in the parsing of Excel spreadsheets can be exploited to corrupt
    memory via a specially crafted Excel file.

  - An error in the processing of certain record objects can be
    exploited to corrupt memory via a specially crafted Excel file.

  - Another error in the processing of certain record objects can be
    exploited to corrupt memory via a specially crafted Excel file.

  - An error in the processing of Binary File Format (BIFF) records
    can be exploited to cause a heap-based buffer overflow via a specially
    crafted Excel file.

  - An error in the handling of formulas embedded inside a cell can
    be exploited to corrupt memory via a specially crafted Excel file.

  - An error when loading Excel formulas can be exploited to corrupt
    a pointer when a specially crafted Excel file is being opened.

  - An error when loading Excel records can be exploited to corrupt
    memory via a specially crafted Excel file.

  - An error when processing Excel record objects can be exploited
    via a specially crafted Excel file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-067.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^1[0-2]\.")
{
  if(version_in_range(version:excelVer, test_version:"10.0", test_version2:"10.0.6855.9")||
     version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8315.9")||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6514.4999"))
  {
    report = report_fixed_ver(installed_version:excelVer, vulnerable_range:"10.0 - 10.0.6855.9, 11.0 - 11.0.8315.9, 12.0 - 12.0.6514.4999");
    security_message(port:0, data:report);
    exit(0);
  }
}

cmptpVer = get_kb_item("SMB/Office/ComptPack/Version");
if(cmptpVer =~ "^12\.")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer =~ "^12\.")
  {
    if(version_in_range(version:xlcnvVer, test_version:"12.0", test_version2:"12.0.6514.4999"))
    {
      report = report_fixed_ver(installed_version:xlcnvVer, vulnerable_range:"12.0 - 12.0.6514.4999");
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

xlviewVer = get_kb_item("SMB/Office/XLView/Version");
if(xlviewVer =~ "^1[12]\.")
{
  if(version_in_range(version:xlviewVer, test_version:"11.0", test_version2:"11.0.8312.9") ||
     version_in_range(version:xlviewVer, test_version:"12.0", test_version2:"12.0.6514.4999")){
    report = report_fixed_ver(installed_version:xlviewVer, vulnerable_range:"11.0 - 11.0.8312.9, 12.0 - 12.0.6514.4999");
    security_message(port:0, data:report);
  }
}
