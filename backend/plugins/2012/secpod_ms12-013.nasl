###############################################################################
# OpenVAS Vulnerability Test
#
# MS Windows C Run-Time Library Remote Code Execution Vulnerability (2654428)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902653");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-0150");
  script_bugtraq_id(51913);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-02-15 12:27:37 +0530 (Wed, 15 Feb 2012)");
  script_name("MS Windows C Run-Time Library Remote Code Execution Vulnerability (2654428)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47949/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2654428");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-013");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code as the logged-on user.");

  script_tag(name:"affected", value:"Microsoft Windows 7 Service Pack 1 and prior.

  Microsoft Windows Vista Service Pack 2 and prior.

  Microsoft Windows Server 2008 Service Pack 2 and prior.");

  script_tag(name:"insight", value:"The flaw is due to the way 'Msvcrt.dll' calculates the size of a
  buffer in memory, allowing data to be copied into memory that has not been properly allocated.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-013.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS12-013 Hotfix (2654428)
if(hotfix_missing(name:"2654428") == 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(! sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Msvcrt.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"7.0.6002.18551") ||
     version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22754")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"7.0.7600.16930") ||
     version_in_range(version:dllVer, test_version:"7.0.7600.20000", test_version2:"7.0.7600.21107")||
     version_in_range(version:dllVer, test_version:"7.0.7601.17000", test_version2:"7.0.7601.17743")||
     version_in_range(version:dllVer, test_version:"7.0.7601.21000", test_version2:"7.0.7601.21877")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
