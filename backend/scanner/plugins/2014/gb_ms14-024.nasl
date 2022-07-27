###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Security Feature Bypass Vulnerability (2961033)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
#  Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804451");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-1809");
  script_bugtraq_id(67273);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-05-14 13:48:02 +0530 (Wed, 14 May 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft Office Security Feature Bypass Vulnerability (2961033)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-024.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A security feature bypass flaw exists
  because the MSCOMCTL common controls library used by Microsoft Office
  software does not properly implement Address Space Layout Randomization
  (ASLR).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass the ASLR security feature, which helps protect users from a
  broad class of vulnerabilities.");

  script_tag(name:"affected", value:"Microsoft Office 2007 Service Pack 3
  Microsoft Office 2010 Service Pack 2 and prior
  Microsoft Office 2013 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");


  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2961033");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2880508");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2589288");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-024");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## MS Office 2013
offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mscomctl.Ocx");
sysVer1 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msstdfmt.dll");
if(sysVer || sysVer1)
{
  if(offVer =~ "^[12|14|15].*")
  {
    if(version_is_less(version:sysVer, test_version:"6.1.98.39"))
    {
      report = "File checked:      system32\Mscomctl.Ocx\n" +
               "File version:     " + sysVer  + "\n" +
               "Vulnerable range:  Less than  6.1.98.39\n" ;
      security_message(data:report);
      exit(0);
    }
  }

  if(offVer =~ "^12.*")
  {
    if(version_is_less(version:sysVer1, test_version:"6.1.98.39"))
    {
       report = "File checked:     system32\Msstdfmt.dll\n" +
                "File version:    " + sysVer1  + "\n" +
                "Vulnerable range: Less than  6.1.98.39\n" ;
       security_message(data:report);
       exit(0);
    }
  }
}

if(offVer =~ "^[12|14].*")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                           item:"CommonFilesDir");
  if(path)
  {
    filePath = path + "\DESIGNER";
    fileVer = fetch_file_version(sysPath:filePath, file_name:"\Msaddndr.dll");

    if(fileVer)
    {
      if(version_is_less(version:fileVer, test_version:"6.1.98.39"))
      {
        report = "File checked: " + filePath + "\Msaddndr.dll\n" +
                 "File version: " + fileVer +  "\n" +
                 "Vulnerable range: Less than  6.1.98.39\n" ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}
