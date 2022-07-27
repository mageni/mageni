###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Multiple RCE and Information Disclosure Vulnerabilities (4013075)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810834");
  script_version("2019-05-03T11:57:32+0000");
  script_cve_id("CVE-2017-0060", "CVE-2017-0073", "CVE-2017-0108", "CVE-2017-0014");
  script_bugtraq_id(96713, 96637, 96722, 96013);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 11:57:32 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-03-30 14:40:25 +0530 (Thu, 30 Mar 2017)");
  script_name("Microsoft Office Multiple RCE and Information Disclosure Vulnerabilities (4013075)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS17-013.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to the way that the
  Windows Graphics Device Interface (GDI) handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code, could take control of the affected system.
  An attacker could then install programs. View, change, or delete data, or
  create new accounts with full user rights.");

  script_tag(name:"affected", value:"Microsoft Office 2007 Service Pack 3

  Microsoft Office 2010 Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3127945");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3141535");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3178688");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3127958");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-013");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## MS Office 2007/2010

OfficeVer = get_kb_item("MS/Office/Ver");
if(!OfficeVer  || OfficeVer !~ "^(12|14).*"){
  exit(0);
}

msPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(msPath)
{
  foreach ver (make_list("OFFICE12", "OFFICE14"))
  {
    offPath = msPath + "\Microsoft Shared\" + ver;
    msdllVer = fetch_file_version(sysPath:offPath, file_name:"Ogl.dll");

    msPath =  msPath +  "\Microsoft Office\" + ver;
    dllVer = fetch_file_version(sysPath:msPath, file_name:"Usp10.dll");

    if(msdllVer)
    {
      if(msdllVer =~ "^12"){
        Vulnerable_range  =  "12.0 - 12.0.6764.4999";
      }
      else if(msdllVer =~ "^14"){
        Vulnerable_range  =  "14.0 - 14.0.7179.4999";
      }

      if(version_in_range(version:msdllVer, test_version:"14.0", test_version2:"14.0.7179.4999") ||
         version_in_range(version:msdllVer, test_version:"12.0", test_version2:"12.0.6764.4999"))
      {
        report = 'File checked:     ' + offPath + "\Ogl.dll" + '\n' +
                 'File version:     ' + msdllVer  + '\n' +
                 'Vulnerable range: ' + Vulnerable_range + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }

    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"1.0626.6002.00000", test_version2:"1.0626.6002.24057"))
      {
        VULN1 = TRUE;
        Vulnerable_range1 = "1.0626.6002.00000 - 1.0626.6002.24057" ;
      }
      else if(version_in_range(version:dllVer, test_version:"1.0626.7601.00000", test_version2:"1.0626.7601.23667"))
      {
        VULN1 = TRUE;
        Vulnerable_range1 = "1.0626.7601.00000 - 1.0626.7601.23667";
      }

      if(VULN1)
      {
        report = 'File checked:     ' + msPath + "Usp10.dll" + '\n' +
                 'File version:     ' + dllVer  + '\n' +
                 'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}
