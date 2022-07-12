###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Word Remote Code Execution Vulnerabilities (2742319)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902926");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-0182", "CVE-2012-2528");
  script_bugtraq_id(55780, 55781);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-10-10 08:46:36 +0530 (Wed, 10 Oct 2012)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerabilities (2742319)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl",
                      "gb_ms_office_web_apps_detect.nasl", "gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Prdts/Installed", "MS/SharePoint/Server_or_Foundation_or_Services/Installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50835/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2598237");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687401");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687315");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687314");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553488");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687485");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687483");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-064");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted word and RTF files.");

  script_tag(name:"affected", value:"Microsoft Word Viewer

  Microsoft Office 2003 Service Pack 3

  Microsoft Office 2007 Service Pack 2

  Microsoft Office 2007 Service Pack 3

  Microsoft Office 2010 Service Pack 1

  Microsoft Office Web Apps 2010 Service Pack 1

  Microsoft SharePoint Server 2010 Service Pack 1

  Microsoft Office Compatibility Pack Service Pack 2

  Microsoft Office Compatibility Pack Service Pack 3");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-064.");

  script_tag(name:"insight", value:"-  An error when parsing the PAPX section can be exploited to corrupt memory
     via a specially crafted Word file.

     NOTE: This vulnerability affects Microsoft Word 2007 only.

  - A use-after-free error exists when handling listid and can be exploited
    via a specially crafted RTF file.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

winwordVer = get_kb_item("SMB/Office/Word/Version");
if(winwordVer =~ "^1[124]\.")
{
  if(version_in_range(version:winwordVer, test_version:"11.0", test_version2:"11.0.8347") ||
     version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6662.5002") ||
     version_in_range(version:winwordVer, test_version:"14.0", test_version2:"14.0.6123.5004"))
  {
    report = report_fixed_ver(installed_version:winwordVer, vulnerable_range:"11.0 - 11.0.8347, 12.0 - 12.0.6662.5002, 14.0 - 14.0.6123.5004");
    security_message(port:0, data:report);
    exit(0);
  }
}

wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
if(wordcnvVer)
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
  if(path)
  {
    path = "\Microsoft Office\Office12";
    sysVer = fetch_file_version(sysPath:path, file_name:"Wordcnv.dll");
    if(sysVer =~ "^12\.")
    {
      if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6662.5002"))
      {
        report = report_fixed_ver(installed_version:sysVer, file_checked:path + "Wordcnv.dll", vulnerable_range:"12.0 - 12.0.6662.5002");
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

wordviewVer = get_kb_item("SMB/Office/WordView/Version");
if(wordviewVer =~ "^11\.")
{
  if(version_in_range(version:wordviewVer, test_version:"11.0", test_version2:"11.0.8347"))
  {
    report = report_fixed_ver(installed_version:wordviewVer, vulnerable_range:"11.0 - 11.0.8347");
    security_message(port:0, data:report);
    exit(0);
  }
}

CPE = "cpe:/a:microsoft:sharepoint_server";
if(version = get_app_version(cpe:CPE))
{
  if(version =~ "^14\.")
  {
    key = "SOFTWARE\Microsoft\Office Server\14.0";
    file = "Msoserver.Dll"; ## File is not mentioned in bulletin, Based on the after applying patch it is taken.
  }

  if(key && registry_key_exists(key:key) && file)
  {
    if(path = registry_get_sz(key:key, item:"BinPath"))
    {
      dllVer = fetch_file_version(sysPath:path, file_name:file);
      if(dllVer =~ "^14\.")
      {
        if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6123.5000"))
        {
          report = report_fixed_ver(installed_version:dllVer, file_checked:path + file, vulnerable_range:"14.0 - 14.0.6123.5000");
          security_message(port:0, data:report);
          exit(0);
        }
      }
    }
  }
}

CPE = "cpe:/a:microsoft:office_web_apps";
if(version = get_app_version(cpe:CPE))
{
  if(version =~ "^14\.")
  {
    path = get_kb_item("MS/Office/Web/Apps/Path");
    if(path && "Could not find the install" >!< path)
    {
      path = path + "\14.0\WebServices\ConversionService\Bin\Converter";
      dllVer = fetch_file_version(sysPath:path, file_name:"msoserver.dll");
      if(dllVer =~ "^14\.")
      {
        if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6123.5000"))
        {
          report = report_fixed_ver(installed_version:dllVer, file_checked:path + "msoserver.dll", vulnerable_range:"14.0 - 14.0.6123.5000");
          security_message(port:0, data:report);
          exit(0);
        }
      }
    }
  }
}
