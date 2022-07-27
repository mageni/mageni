###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Authentication Bypass and Spoofing Vulnerabilities (2836440)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903308");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-1336", "CVE-2013-1337");
  script_bugtraq_id(59789, 59790);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-05-15 12:23:29 +0530 (Wed, 15 May 2013)");
  script_name("Microsoft .NET Framework Authentication Bypass and Spoofing Vulnerabilities (2836440)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53350");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-040");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to bypass security mechanism
  and gain access to restricted endpoint functions.");
  script_tag(name:"affected", value:"Microsoft .NET Framework 4
  Microsoft .NET Framework 4.5
  Microsoft .NET Framework 3.5
  Microsoft .NET Framework 3.5.1
  Microsoft .NET Framework 2.0 Service Pack 2");
  script_tag(name:"insight", value:"The flaws are due to

  - Improper validation of XML signatures by the CLR

  - Error within the WCF endpoint authentication mechanism when handling
    queries");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-040.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2, win8:1, win2012:1) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(registry_key_exists(key:key))
{
  foreach item (registry_enum_keys(key:key))
  {
    path = registry_get_sz(key:key + item, item:"Path");
    if(path && "\Microsoft.NET\Framework" >< path)
    {
      dllVer = fetch_file_version(sysPath:path, file_name:"System.Security.dll");

      ## .NET Framework 4.5 and 3.5 on Windows 8 and Windows Server 2012
      if(dllVer && (hotfix_check_sp(win8:1, win2012:1) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18038")||
           version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19057")||
           version_in_range(version:dllVer, test_version:"2.0.50727.6000", test_version2:"2.0.50727.6403")||
           version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7017"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      ## .NET Framework 4.5 , 4.0 and 3.5.1 on Windows 7 Service Pack 1, Windows Server 2008 R2 Service Pack 1
      if(dllVer && (hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5468")||
           version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7017")||
           version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1003")||
           version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2005")||
           version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18037")||
           version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19056"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      ## .NET Framework 4.5, 4.0 and 2.0 SP 2 on Windows Vista and Windows Server 2008
      if(dllVer && (hotfix_check_sp(winVista:3, win2008:3) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.0000", test_version2:"2.0.50727.4236")||
           version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7017")||
           version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1003")||
           version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2005")||
           version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18037")||
           version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19056"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      ## .NET Framework 4.0 and 2.0 Service Pack 2 on Windows XP and Windows Server 2003
      if(dllVer && (hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1003")||
           version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2005")||
           version_in_range(version:dllVer, test_version:"2.0.50727.0000", test_version2:"2.0.50727.3645")||
           version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7018"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}
