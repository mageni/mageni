###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Suite Remote Code Execution Vulnerabilities (3185852)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807361");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0137", "CVE-2016-0141", "CVE-2016-3357");
  script_bugtraq_id(92903, 92786);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-09-14 11:55:19 +0530 (Wed, 14 Sep 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Suite Remote Code Execution Vulnerabilities (3185852)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-107.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as office software
  fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office 2003 Service Pack 3
  Microsoft Office 2010 Service Pack 2
  Microsoft Office 2013 Service Pack 1
  Microsoft Office 2016 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3118268");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3118292");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2553432");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3118297");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3118309");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-107");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

## MS Office
offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!path){
  exit(0);
}

if(offVer =~ "^(11|14|15|16)\..*")
{
  foreach offsubver (make_list("Office11", "Office15", "Office14", "Office16"))
  {
    offPath = path + "\Microsoft Shared\" + offsubver;
    offexeVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");
    if(offexeVer)
    {
      if(offexeVer =~ "^11"){
        Vulnerable_range3  =  "11.0 - 11.0.8433";
      }
      else if(offexeVer =~ "^14"){
        Vulnerable_range3  =  "14 - 14.0.7173.0999";
      }
      else if(offexeVer =~ "^15"){
        Vulnerable_range3  =  "15 - 15.0.4859.0999";
      }
      else if(offexeVer =~ "^16"){
        Vulnerable_range3  =  "16 - 16.0.4432.0999";
      }

      if(version_in_range(version:offexeVer, test_version:"11.0", test_version2:"11.0.8433") ||
         version_in_range(version:offexeVer, test_version:"14.0", test_version2:"14.0.7173.0999") ||
         version_in_range(version:offexeVer, test_version:"15.0", test_version2:"15.0.4859.0999") ||
         version_in_range(version:offexeVer, test_version:"16.0", test_version2:"16.0.4432.0999"))
      {
        report = 'File checked:     ' + offPath + "\Mso.dll" + '\n' +
                 'File version:     ' + offexeVer  + '\n' +
                 'Vulnerable range: ' + Vulnerable_range3 + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}
