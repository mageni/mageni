###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office 2013 Service Pack 1 Remote Code Execution Vulnerabilities (KB4011580)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812618");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2018-0798", "CVE-2018-0801", "CVE-2018-0802", "CVE-2018-0812");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-01-10 11:52:29 +0530 (Wed, 10 Jan 2018)");
  script_name("Microsoft Office 2013 Service Pack 1 Remote Code Execution Vulnerabilities (KB4011580)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011580");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists as Microsoft Office
  software fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011580");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

## MS Office Version
officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer){
  exit(0);
}

commonpath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!commonpath){
  exit(0);
}

if(officeVer =~ "^(15\.)")
{
  offPath = commonpath + "\Microsoft Shared\EQUATION" ;
  msdllVer = fetch_file_version(sysPath:offPath, file_name:"eqnedt32.exe");
  ##This Update removes file eqnedt32.exe from offPath
  if(!msdllVer){
    exit(0);
  } else
  {
    report = report_fixed_ver( file_checked:offPath + "\eqnedt32.exe",
                               file_version:msdllVer, vulnerable_range:"File 'eqnedt32.exe' present");
    security_message(data:report);
    exit(0);
  }
}
exit(0);
