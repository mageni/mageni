###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Suite Remote Code Execution Vulnerabilities (3104540)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806158");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2015-6093", "CVE-2015-6092", "CVE-2015-6091");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-11-11 12:28:18 +0530 (Wed, 11 Nov 2015)");
  script_name("Microsoft Office Suite Remote Code Execution Vulnerabilities (3104540)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-116.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists when,

  - The Office software improperly handles objects in memory while parsing
    specially crafted Office files.

  - The Office software fails to properly handle rich text format files in
    memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and
  to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office 2007 Service Pack 3 and prior

  Microsoft Office 2010 Service Pack 2 and prior

  Microsoft Office 2013 Service Pack 1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3104540");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3101555");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3101529");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3101521");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3101360");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-116");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_office_detection_900025.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");

  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms15-116");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2007,2010, 2015
if(officeVer && officeVer =~ "^1[245]\.")
{
  InsPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  if(InsPath)
  {
    foreach offsubver (make_list("Office12", "Office15", "Office14"))
    {
      offPath = InsPath + "\Microsoft Shared\" + offsubver;
      exeVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");
      if(exeVer)
      {
        if(exeVer =~ "^12"){
          Vulnerable_range  =  "12.0 - 12.0.6735.4999";
        }
        else if(exeVer =~ "^14"){
          Vulnerable_range  =  "14 - 14.0.7162.4999";
        }
        else if(exeVer =~ "^15"){
          Vulnerable_range  =  "15 - 15.0.4771.1000";
        }
      }

      ## For office 2010 Wwlibcxm.dll is mentioned and it is not available so ignoring
      if(exeVer)
      {
        if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6735.4999") ||
           version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7162.4999") ||
           version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4771.1000"))
        {

          report = 'File checked:     ' + offPath + "\mso.dll" + '\n' +
                   'File version:     ' + exeVer  + '\n' +
                   'Vulnerable range: ' + Vulnerable_range + '\n' ;
          security_message(data:report);
          exit(0);
        }
      }
    }
  }
}
