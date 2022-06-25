###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows DirectWrite Denial of Service Vulnerability (2665364)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902908");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-0156");
  script_bugtraq_id(52332);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-03-14 09:53:40 +0530 (Wed, 14 Mar 2012)");
  script_name("Microsoft Windows DirectWrite Denial of Service Vulnerability (2665364)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48361");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2665364");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-019");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial
  of service.");

  script_tag(name:"affected", value:"Microsoft Windows 7 Service Pack 1 and prior

  Microsoft Windows Vista Service Pack 2 and prior

  Microsoft Windows Server 2008 Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaw is due to an error in DirectWrite and can be exploited to
  cause an application using the API to stop responding via a specially crafted sequence of unicode characters.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host has moderate security update missing according to
  Microsoft Bulletin MS12-019.");

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

## MS12-019 Hotfix (2665364)
if(hotfix_missing(name:"2665364") == 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\D3d10_1.dll");
if(sysVer)
{
  if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:sysVer, test_version:"7.0.6002.18582") ||
       version_in_range(version:sysVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22796")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Dwrite.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win7:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7600.16961") ||
     version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21147")||
     version_in_range(version:dllVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17775")||
     version_in_range(version:dllVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21919")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
