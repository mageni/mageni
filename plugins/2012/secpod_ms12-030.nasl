###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Remote Code Execution Vulnerabilities (2663830)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903026");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-0141", "CVE-2012-0142", "CVE-2012-0143", "CVE-2012-0184",
                "CVE-2012-0185", "CVE-2012-1847");
  script_bugtraq_id(53342, 53373, 53374, 53375, 53379);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-05-09 10:19:21 +0530 (Wed, 09 May 2012)");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2663830)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2597086");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2597161");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2597969");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2596842");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2597162");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2597166");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553371");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-030");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/Excel/Version", "MS/Office/Ver", "SMB/Office/XLView/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  with the privileges of the user running the affected application.");

  script_tag(name:"affected", value:"Microsoft Excel Viewer

  Microsoft Excel 2003 Service Pack 3

  Microsoft Excel 2010 Service Pack 1 and prior

  Microsoft Office 2010 Service Pack 1 and prior

  Microsoft Excel 2007 Service Pack 2 and Service Pack 3

  Microsoft Office 2007 Service Pack 2 and Service Pack 3

  Microsoft Office Compatibility Pack Service Pack 2 and Service Pack 3");

  script_tag(name:"insight", value:"The flaws are due to errors while handling OBJECTLINK record,
  SXLI record, MergeCells record and an mismatch error when handling the Series
  record within Excel files.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-030.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer && excelVer =~ "^1[124]\.0")
{
  if(version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8345") ||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6661.4999") ||
     version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.6117.5002"))
  {
    report = report_fixed_ver(installed_version:excelVer, vulnerable_range:"11.0 - 11.0.8345, 12.0 - 12.0.6661.4999, 14.0 - 14.0.6117.5002");
    security_message(port:0, data:report);
    exit(0);
  }

  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Excel.exe", item:"Path");
  if(path)
  {
    graphVer = fetch_file_version(sysPath:path, file_name:"graph.exe");
    if(graphVer && graphVer =~ "^1[24]\.0")
    {
      if(version_in_range(version:graphVer, test_version:"12.0", test_version2:"12.0.6658.5003") ||
         version_in_range(version:graphVer, test_version:"14.0", test_version2:"14.0.6117.5002"))
      {
        report = report_fixed_ver(installed_version:graphVer, vulnerable_range:"12.0 - 12.0.6658.5003, 14.0 - 14.0.6117.5002");
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

excelviewVer = get_kb_item("SMB/Office/XLView/Version");
if(excelviewVer && excelviewVer =~ "^12\.0")
{
  if(version_in_range(version:excelviewVer, test_version:"12.0", test_version2:"12.0.6658.5003"))
  {
    report = report_fixed_ver(installed_version:excelviewVer, vulnerable_range:"12.0 - 12.0.6658.5003");
    security_message(port:0, data:report);
    exit(0);
  }
}

cmptPckVer = get_kb_item("SMB/Office/ComptPack/Version");
if(cmptPckVer && cmptPckVer =~ "^12\.0")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer && xlcnvVer =~ "^12\.0")
  {
    if(version_in_range(version:xlcnvVer, test_version:"12.0", test_version2:"12.0.6661.4999")){
      report = report_fixed_ver(installed_version:cmptPckVer, vulnerable_range:"12.0 - 12.0.6661.4999");
      security_message(port:0, data:report);
    }
  }
}
