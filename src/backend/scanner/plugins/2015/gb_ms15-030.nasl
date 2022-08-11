###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Remote Desktop Denial of Service Vulnerability (3039976)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805500");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2015-0079");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-03-11 09:50:50 +0530 (Wed, 11 Mar 2015)");
  script_name("Microsoft Windows Remote Desktop Denial of Service Vulnerability (3039976)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-030.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to error in the Remote Desktop
  Protocol (RDP) that is triggered when handling multiple RDP sessions that fail
  to properly free objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause an exhaustion of memory resources and cause the system to
  stop responding.");

  script_tag(name:"affected", value:"Microsoft Windows 8 x32/x64
  Microsoft Windows 8.1 x32/x64
  Microsoft Windows Server 2012
  Microsoft Windows Server 2012 R2
  Microsoft Windows 7 x32/x64 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3039976");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3036493");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3035017");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-030");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win8:1, win8x64:1,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1) <= 0)
{
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

RdpVer = fetch_file_version(sysPath:sysPath, file_name:"\system32\Rdpcorets.dll");
if(!RdpVer){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2))
{
  rdpVer = fetch_file_version(sysPath:sysPath, file_name:"\system32\mstsc.exe");

  ## Enterprise and Ultimate editions of Windows 7 are affected,
  ## All supported editions of Windows 7 are affected if RDP 8.0 is installed on the system.
  key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
  edition = registry_get_sz(key:key, item:"EditionID");

  ## RDP Protocol Version 8.0 = 6.2.9200.16465
  if("Ultimate" >< edition || "Enterprise" >< edition || rdpVer =~ "^(6\.2\.9200)")
  {
    if(version_is_less(version:RdpVer, test_version:"6.1.7601.18740") ||
       version_in_range(version:RdpVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22946") ||
       version_in_range(version:RdpVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.17052") ||
       version_in_range(version:RdpVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21171")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}

if(hotfix_check_sp(win8:1) > 0)
{
  if(version_is_less(version:RdpVer, test_version:"6.2.9200.17247") ||
     version_in_range(version:RdpVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21363")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:RdpVer, test_version:"6.3.9600.17667")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win8x64:1, win2012:1) > 0)
{
  sysVer2 = fetch_file_version(sysPath:sysPath, file_name:"\system32\Rdpudd.dll");
  if(!sysVer2){
    exit(0);
  }

  if(version_is_less(version:sysVer2, test_version:"6.2.9200.17247") ||
     version_in_range(version:sysVer2, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21363")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
