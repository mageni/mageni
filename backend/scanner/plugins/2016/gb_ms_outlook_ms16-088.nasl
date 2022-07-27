###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Outlook Remote Code Execution Vulnerability (3170008)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807862");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2016-3278");
  script_bugtraq_id(91574);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2016-07-13 12:44:21 +0530 (Wed, 13 Jul 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Outlook Remote Code Execution Vulnerability (3170008)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-088.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists as office software fails to
  properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow a to execute
  arbitrary code in the context of the current user and to take control of the
  affected system.");

  script_tag(name:"affected", value:"Microsoft Outlook 2010 Service Pack 2 and prior,

  Microsoft Outlook 2013 Service Pack 1 and prior,

  Microsoft Outlook 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115259");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115279");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115246");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-088");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/Outlook/Version");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

outlookVer = get_kb_item("SMB/Office/Outlook/Version");

if(!outlookVer || outlookVer !~ "^1[4-6]\."){
  exit(0);
}

## Office outlook
outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\OUTLOOK.EXE", item:"Path");
if(outlookFile)
{
  outlookVer = fetch_file_version(sysPath:outlookFile, file_name:"outlook.exe");
  if(outlookVer)
  {
    if(version_in_range(version:outlookVer, test_version:"14.0", test_version2:"14.0.7169.4999"))
    {
      Vulnerable_range = "14.0 - 14.0.7169.4999";
      VULN = TRUE ;
    }
    else if(version_in_range(version:outlookVer, test_version:"15.0", test_version2:"15.0.4841.0999"))
    {
      Vulnerable_range = "15.0 - 15.0.4841.0999";
      VULN = TRUE ;
    }
    else if(version_in_range(version:outlookVer, test_version:"16.0", test_version2:"16.0.4405.0999"))
    {
      Vulnerable_range = "16.0 - 16.0.4405.0999";
      VULN = TRUE ;
    }
  }
}

if(VULN)
{
  report = 'File checked:     ' +  outlookFile + "\outlook.exe" + '\n' +
           'File version:     ' +  outlookVer  + '\n' +
           'Vulnerable range: ' +  Vulnerable_range + '\n' ;

  security_message(data:report);
  exit(0);
}
