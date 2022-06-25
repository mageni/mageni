###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Remote Code Execution Vulnerabilities (2878890)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.903412");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-3128", "CVE-2013-3860", "CVE-2013-3861");
  script_bugtraq_id(62819, 62820, 62807);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-10-09 12:14:29 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerabilities (2878890)");

  script_tag(name:"summary", value:"This host is missing an critical security update according to
  Microsoft Bulletin MS13-082.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An unspecified error when handling OpenType fonts (OTF).

  - An error when when expanding entity references.

  - An unspecified error when parsing JSON data.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 2.x

  Microsoft .NET Framework 3.x

  Microsoft .NET Framework 4.x");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute the arbitrary
  code, exhaust available system resource, cause a DoS (Denial of Service) and compromise the system.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55043");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2878890");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-082");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

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

      ## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008,
      ##  Windows 7 and and Windows Server 2008 R2
      if(dllVer && (hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2) >0 ))
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1015")||
           version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2025"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      ## .NET Framework 4.5 on Windows 8 and Windows Server 2012
      ## .NET Framework 3.5 on Windows 8 and Windows Server 2012
      if(dllVer && (hotfix_check_sp(win8:1, win2012:1) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18055")||
           version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19108")||
           version_in_range(version:dllVer, test_version:"2.0.50727.6000", test_version2:"2.0.50727.6409")||
           version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7031"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      ## .NET Framework 4.5 on Windows Vista Service Pack 2, Windows Server 2008 Service Pack 2,
      if(dllVer && (hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0))
      {
         if(version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18054") ||
            version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19107"))
         {
           security_message( port: 0, data: "The target host was found to be vulnerable" );
           exit(0);
         }
      }

      ## .NET Framework 3.5.1 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
      if((dllVer && hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5474")||
           version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7031"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if(dllVer && (hotfix_check_sp(winVista:3, win2008:3) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4244")||
           version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7031"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
     }

      ## .NET Framework 2.0 Service Pack 2 on Windows XP and Windows Server 2003
      if(dllVer && (hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3651")||
           version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7031"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}


## .NET Framework 4.5 on Windows Vista Service Pack 2 and
##  Windows Server 2008 Service Pack 2
key = "SOFTWARE\Microsoft\ASP.NET\4.0.30319.0";
if(registry_key_exists(key:key))
{
  path = registry_get_sz(key:key, item:"Path");
  if(path){
    dllv4 = fetch_file_version(sysPath:path, file_name:"WPF\Wpftxt_v0400.dll");
  }

  ## .NET Framework 4.5 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
  if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_in_range(version:dllv4, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18058") ||
       version_in_range(version:dllv4, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19113"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  ## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008,
  if(hotfix_check_sp(xp:4, win2003:3, win2003x64:3, winVista:3, win2008:3) > 0)
  {
    if(version_in_range(version:dllv4, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1013") ||
       version_in_range(version:dllv4, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2020"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}


sysPath = smb_get_systemroot();
if(sysPath )
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\presentationcffrasterizernative_v0300.dll");

  ## .NET Framework 3.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
  if(dllVer && (hotfix_check_sp(winVista:3, win2008:3) > 0))
  {
    if(version_in_range(version:dllVer, test_version:"3.0.6920.4000", test_version2:"3.0.6920.4217") ||
       version_in_range(version:dllVer, test_version:"3.0.6920.7000", test_version2:"3.0.6920.7061"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  ## NET Framework 3.5.1 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
  if((dllVer && hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0))
  {
    if(version_in_range(version:dllVer, test_version:"3.0.6920.5000", test_version2:"3.0.6920.5458")||
       version_in_range(version:dllVer, test_version:"3.0.6920.7000", test_version2:"3.0.6920.7061"))
    {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
    }
  }

  ## NET Framework 3.0 Service Pack 2 on Windows XP Service Pack 2 and Windows Server 2003 Service Pack 2
  if(dllVer && (hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0))
  {
    if(version_in_range(version:dllVer, test_version:"3.0.6920.4000", test_version2:"3.0.6920.4057")||
       version_in_range(version:dllVer, test_version:"3.0.6920.7000", test_version2:"3.0.6920.7060"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  ## .NET Framework 3.5 on Windows 8 and Windows Server 2012
  if(dllVer && (hotfix_check_sp(win8:1, win2012:1) > 0))
  {
    if(version_in_range(version:dllVer, test_version:"3.0.6920.6000", test_version2:"3.0.6920.6408") ||
       version_in_range(version:dllVer, test_version:"3.0.6920.7000", test_version2:"3.0.6920.7061"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
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
if(!dllv3) {
  exit(0);
}

## .NET Framework 3.5 SP1 on Windows Server 2003, Windows Server 2008, Windows Vista, and Windows XP
if(dllv3 && (hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3) > 0))
{
  if(version_in_range(version:dllv3, test_version:"3.5.30729.4000", test_version2:"3.5.30729.4055")||
     version_in_range(version:dllv3, test_version:"3.5.30729.7000", test_version2:"3.5.30729.7055"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

##.NET Framework 3.5 on Windows 8 and Windows Server 2012
if(dllv3 && (hotfix_check_sp(win8:1, win2012:1) > 0))
{
   if(version_in_range(version:dllv3, test_version:"3.5.30729.4000", test_version2:"3.5.30729.6406")||
      version_in_range(version:dllv3, test_version:"3.5.30729.7000", test_version2:"3.5.30729.7056"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

##.NET Framework 3.5.1 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
if((dllv3 && hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0))
{
  if(version_in_range(version:dllv3, test_version:"3.5.30729.5000", test_version2:"3.5.30729.5457")||
     version_in_range(version:dllv3, test_version:"3.5.30729.7000", test_version2:"3.5.30729.7056"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
