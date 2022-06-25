###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Multiple Remote Code Execution Vulnerabilities (3177393)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807873");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-3301", "CVE-2016-3303", "CVE-2016-3304");
  script_bugtraq_id(92288, 92301, 92302);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-08-10 14:44:44 +0530 (Wed, 10 Aug 2016)");
  script_name("Microsoft Office Multiple Remote Code Execution Vulnerabilities (3177393)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-097.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to the windows font
  library which improperly handles specially crafted embedded fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft Office 2007 Service Pack 3

  Microsoft Office 2010 Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115109");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115131");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-097");

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

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2007/2010
if(!officeVer || officeVer !~ "^1[24]\."){
  exit(0);
}

msPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
if(msPath)
{
  foreach ver (make_list("OFFICE12", "OFFICE14"))
  {
    offPath = msPath + "\Microsoft Shared\" + ver;
    msdllVer = fetch_file_version(sysPath:offPath, file_name:"Ogl.dll");

    if(msdllVer)
    {
      if(msdllVer =~ "^12\."){
        Vulnerable_range  =  "12.0 - 12.0.6751.4999";
      }
      else if(msdllVer =~ "^14\."){
        Vulnerable_range  =  "14.0 - 14.0.7172.4999";
      }

      if(version_in_range(version:msdllVer, test_version:"14.0", test_version2:"14.0.7172.4999") ||
         version_in_range(version:msdllVer, test_version:"12.0", test_version2:"12.0.6751.4999"))
      {
        report = 'File checked:     ' + offPath + "\Ogl.dll" + '\n' +
                 'File version:     ' + msdllVer  + '\n' +
                 'Vulnerable range: ' + Vulnerable_range + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}
