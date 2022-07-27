###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office 2010 Service Pack 2 Remote Code Execution Vulnerability (KB3213631)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811743");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2017-8696");
  script_bugtraq_id(100780);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-13 09:02:09 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Office 2010 Service Pack 2 Remote Code Execution Vulnerability (KB3213631)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB3213631");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the way Windows Uniscribe
  handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker who
  successfully exploited this vulnerability to take control of the affected system.");

  script_tag(name:"affected", value:"Microsoft Office 2010 Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3213631");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

offVer = get_kb_item("MS/Office/Ver");
if(!offVer || offVer !~ "^14\."){
  exit(0);
}

msPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(msPath)
{
  msPath =  msPath +  "\Microsoft Office\OFFICE14";
  msdllVer = fetch_file_version(sysPath:msPath, file_name:"Usp10.dll");
  if(!msdllVer){
    exit(0);
  }

  if(version_is_less(version:msdllVer, test_version:"1.0626.7601.23883"))
  {
    report = 'File checked:     ' + msPath + "\Usp10.dll" + '\n' +
             'File version:     ' + msdllVer  + '\n' +
             'Vulnerable range: ' + "Less than 1.0626.7601.23883" + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
exit(0);
