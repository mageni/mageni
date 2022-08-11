###############################################################################
# OpenVAS Vulnerability Test
#
# Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (2638420)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902806");
  script_version("2019-05-03T10:54:50+0000");
  script_bugtraq_id(51186);
  script_cve_id("CVE-2011-3414", "CVE-2011-3415", "CVE-2011-3416", "CVE-2011-3417");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-12-30 10:10:10 +0530 (Fri, 30 Dec 2011)");
  script_name("Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (2638420)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47323");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/903934");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2011-003.html");
  script_xref(name:"URL", value:"http://www.nruns.com/_downloads/advisory28122011.pdf");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-100");
  script_xref(name:"URL", value:"http://blogs.technet.com/b/srd/archive/2011/12/27/more-information-about-the-december-2011-asp-net-vulnerability.aspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attacker to cause a denial of service,
  conduct spoofing attacks or bypass certain security restrictions.");
  script_tag(name:"affected", value:"Microsoft .NET Framework 4
  Microsoft .NET Framework 3.5.1
  Microsoft .NET Framework 3.5 Service Pack 1
  Microsoft .NET Framework 2.0 Service Pack 2
  Microsoft .NET Framework 1.1 Service Pack 1");
  script_tag(name:"insight", value:"- An error within ASP.NET when hashing form posts and updating a hash table.
    This can be exploited to cause a hash collision resulting in high CPU
    consumption via a specially crafted form sent in a HTTP POST request.

  - Open redirect vulnerability in the Forms Authentication feature in the
    ASP.NET subsystem allows remote attackers to redirect users to arbitrary
    web sites and conduct phishing attacks via a crafted return URL.

  - The Forms Authentication feature in the ASP.NET subsystem allows remote
    authenticated users to obtain access to arbitrary user accounts via a
    crafted username.

  - The Forms Authentication feature in the ASP.NET subsystem when sliding
    expiry is enabled, does not properly handle cached content, which allows
    remote attackers to obtain access to arbitrary user accounts via a crafted
    URL.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-100.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    if("v4.0" >< path){
      dllv4 = fetch_file_version(sysPath:path, file_name:"System.Web.Extensions.dll");
    }

    if("v2.0" >< path){
      dllv2 = fetch_file_version(sysPath:path, file_name:"System.Web.dll");
    }

    if("v1.1" >< path){
      dllv1 = fetch_file_version(sysPath:path, file_name:"System.Web.dll");
    }
  }
}

## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, Windows 7
if((hotfix_missing(name:"2656351") == 1) && dllv4)
{
  if(version_in_range(version:dllv4, test_version:"4.0.30319.000", test_version2:"4.0.30319.271")||
     version_in_range(version:dllv4, test_version:"4.0.30319.500", test_version2:"4.0.30319.546"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## .NET Framework 2 on Windows XP and Windows Server 2003
if((hotfix_missing(name:"2656352") == 1) && (hotfix_check_sp(xp:4, win2003:3) > 0) && dllv2)
{
  if(version_in_range(version:dllv2, test_version:"2.0.50727.0000", test_version2:"2.0.50727.3633")||
     version_in_range(version:dllv2, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5709"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## .NET Framework 2 on Windows Vista and Windows Server 2008
if((hotfix_missing(name:"2656362") == 1) && (hotfix_check_sp(winVista:3, win2008:3) > 0) && dllv2)
{
  if(version_in_range(version:dllv2, test_version:"2.0.50727.0000", test_version2:"2.0.50727.4222")||
     version_in_range(version:dllv2, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5709"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## .NET Framework 1.1 SP1 on Windows Server 2003 SP2, Windows XP, Windows Vista, and Windows Server 2008
if(dllv1 && (((hotfix_missing(name:"2656358") == 1) && (hotfix_check_sp(win2003:3) > 0)) ||
  ((hotfix_missing(name:"2656353") == 1) && (hotfix_check_sp(xp:4, winVista:3, win2008:3) > 0))))
{
  if(version_in_range(version:dllv1, test_version:"1.1.4322.0", test_version2:"1.1.4322.2493"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

key = "SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.5";
if(!registry_key_exists(key:key)){
  exit(0);
}

path = registry_get_sz(key:key, item:"All Assemblies In");
if(! path) {
  exit(0);
}

dllv3 = fetch_file_version(sysPath:path, file_name:"System.Web.Extensions.dll");
if(! dllv3) {
  exit(0);
}

## .NET Framework 3.5 SP1 on Windows Server 2003, Windows Server 2008, Windows Vista, and Windows XP
if((hotfix_missing(name:"2657424") == 1) && (hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3) > 0))
{
  if(version_in_range(version:dllv3, test_version:"3.5.30729.3000", test_version2:"3.5.30729.3677")||
     version_in_range(version:dllv3, test_version:"3.5.30729.5000", test_version2:"3.5.30729.5768"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## .NET Framework 3.5.1 on Windows 7
if((hotfix_missing(name:"2656355") == 1) && (hotfix_missing(name:"2656356") == 1) && (hotfix_check_sp(win7:2) > 0))
{
  if(version_in_range(version:dllv3, test_version:"3.5.30729.4000", test_version2:"3.5.30729.4957")||
     version_in_range(version:dllv3, test_version:"3.5.30729.5700", test_version2:"3.5.30729.5769")||
     version_in_range(version:dllv3, test_version:"3.5.30729.5400", test_version2:"3.5.30729.5445")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
