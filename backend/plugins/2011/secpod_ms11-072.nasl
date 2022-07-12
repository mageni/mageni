###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Excel Remote Code Execution Vulnerabilities (2587505)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902727");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_cve_id("CVE-2011-1986", "CVE-2011-1987", "CVE-2011-1988",
                "CVE-2011-1989", "CVE-2011-1990");
  script_bugtraq_id(49476, 49477, 49478, 49518, 49517);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office Excel Remote Code Execution Vulnerabilities (2587505)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/Excel/Version", "MS/Office/Ver", "SMB/Office/XLView/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  with the privileges of the user running the affected application.");

  script_tag(name:"affected", value:"Microsoft Excel 2003 Service Pack 3

  Microsoft Excel 2007 Service Pack 2

  Microsoft Office 2007 Service Pack 2

  Microsoft Excel Viewer Service Pack 2

  Microsoft Excel 2010 Service Pack 1 and prior

  Microsoft Office 2010 Service Pack 1 and prior

  Excel Services installed on Microsoft Office SharePoint Server 2007 Service Pack 2

  Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2");

  script_tag(name:"insight", value:"The flaws are caused by memory corruption, array-indexing and use-after-free
  errors when handling the crafted Excel files.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-072.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45932/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553072");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553073");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553089");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-072");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^1[124]\.0")
{
  if(version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8340.0") ||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6565.5002") ||
     version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.6106.5004"))
  {
    report = report_fixed_ver(installed_version:excelVer, vulnerable_range:"11.0 - 11.0.8340.0, 12.0 - 12.0.6565.5002, 14.0 - 14.0.6106.5004");
    security_message(port:0, data:report);
    exit(0);
  }
}

excelVer = get_kb_item("SMB/Office/XLView/Version");
if(excelVer && excelVer =~ "^12\.0")
{
  if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6565.4999"))
  {
    report = report_fixed_ver(installed_version:excelVer, vulnerable_range:"12.0 - 12.0.6565.4999");
    security_message(port:0, data:report);
    exit(0);
  }
}

comptVer = get_kb_item("SMB/Office/ComptPack/Version");
if(comptVer && comptVer =~ "^12\.0")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer && xlcnvVer =~ "^12\.0")
  {
    if(version_in_range(version:xlcnvVer, test_version:"12.0", test_version2:"12.0.6565.5002"))
    {
      report = report_fixed_ver(installed_version:xlcnvVer, vulnerable_range:"12.0 - 12.0.6565.5002");
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

officeVer = get_kb_item("MS/Office/Ver");
if(officeVer && officeVer =~ "^1[24]\.0")
{
  path12 = registry_get_sz(key:"SOFTWARE\Microsoft\Office\12.0\Access\InstallRoot", item:"Path");
  if(path12)
  {
    ort12Ver = fetch_file_version(sysPath:path12, file_name:"Oart.dll");
    ortconv12Ver = fetch_file_version(sysPath:path12, file_name:"Oartconv.dll");
    if(ort12Ver =~ "^12\.0" || ortconv12Ver =~ "^12\.0")
    {
      if(version_in_range(version:ort12Ver, test_version:"12.0", test_version2:"12.0.6565.4999") ||
         version_in_range(version:ortconv12Ver, test_version:"12.0", test_version2:"12.0.6565.4999"))
      {
        report = report_fixed_ver(installed_version:ort12Ver + " / " + ortconv12Ver, vulnerable_range:"12.0 - 12.0.6565.4999");
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }

  path14 = registry_get_sz(key:"SOFTWARE\Microsoft\Office\14.0\Access\InstallRoot", item:"Path");
  if(path14)
  {
    ort14Ver = fetch_file_version(sysPath:path14, file_name:"Oart.dll");
    ortconv14Ver = fetch_file_version(sysPath:path14, file_name:"Oartconv.dll");
    if(ort14Ver =~ "^14\.0" || ortconv14Ver =~ "^14\.0")
    {
      if(version_in_range(version:ort14Ver, test_version:"14.0", test_version2:"14.0.6106.5004") ||
         version_in_range(version:ortconv14Ver, test_version:"14.0", test_version2:"14.0.6106.5004"))
      {
        report = report_fixed_ver(installed_version:ort14Ver + " / " + ortconv14Ver, vulnerable_range:"14.0 - 14.0.6106.5004");
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(item:"DisplayName", key:key + item);
  if("Microsoft Office SharePoint Server 2007" >< appName)
  {
    dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
    if(dllPath)
    {
      dllPath += "\System\Ole DB";
      dllVer = fetch_file_version(sysPath:dllPath, file_name:"Msmdcb80.dll");
      if(dllVer && dllVer =~ "^8\.0")
      {
        if(version_in_range(version:dllVer, test_version:"8.0", test_version2:"8.0.2277.0")){
          report = report_fixed_ver(installed_version:dllVer, vulnerable_range:"8.0 - 8.0.2277.0");
          security_message(port:0, data:report);
        }
      }
    }
  }
}
