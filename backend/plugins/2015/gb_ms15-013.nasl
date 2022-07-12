###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Security Feature Bypass Vulnerability (3033857)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805041");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-6362");
  script_bugtraq_id(72467);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-02-11 08:59:35 +0530 (Wed, 11 Feb 2015)");
  script_name("Microsoft Office Security Feature Bypass Vulnerability (3033857)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-013.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A security feature bypass vulnerability
  exists in Microsoft Office when it fails to use the Address Space Layout
  Randomization (ASLR) security feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to reliably predict the memory offsets of specific instructions
  which may allow arbitrary code execution.");

  script_tag(name:"affected", value:"Microsoft Office 2007 Service Pack 3 and prior

  Microsoft Office 2010 Service Pack 2 and prior

  Microsoft Office 2013 Service Pack 1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3033857");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2910941");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2920748");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2920795");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms15-013");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms15-013");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2007/2010/2013
if(!officeVer || officeVer !~ "^1[245]\."){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(path)
{
  foreach ver (make_list("\OFFICE12", "\OFFICE14", "\OFFICE15"))
  {
    offPath = path + "\Microsoft Office" + ver + "\ADDINS";
    dllVer = fetch_file_version(sysPath:offPath, file_name:"Msvcr71.dll");

    if(dllVer &&
       (version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.10.3077.0")))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
