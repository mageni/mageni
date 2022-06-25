###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Denial of Service Vulnerability (2990931)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804480");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-4072");
  script_bugtraq_id(69603);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-09-10 09:34:51 +0530 (Wed, 10 Sep 2014)");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft .NET Framework Denial of Service Vulnerability (2990931)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-053.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error within
  a hash generation function when hashing requests and can be exploited to
  cause a hash collision resulting in high CPU consumption via specially
  crafted requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to cause a denial of service.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 1.1,
  2.0, 3.0, 3.5, 3.5.1, 4.0, 4.5, 4.5.1 and 4.5.2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60982");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-053");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2,
   win2008:3, win2008r2:2, win8:1, win8x64:1, win8_1:1, win8_1x64:1,
   win2012:1, win2012R2:1) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if(path && "\Microsoft.NET\Framework" >< path)
  {
    dllVer = fetch_file_version(sysPath:path, file_name:"mscorlib.dll");
    if(dllVer)
    {
      ## .NET Framework 1.1 Service Pack 1 for Windows Server 2003 Service Pack 2
      if((hotfix_check_sp(win2003:3, win2003x64:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2509")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 for Windows Server 2003 Service Pack 2
      if((hotfix_check_sp(win2003:3, win2003x64:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3661")||
          version_in_range(version:dllVer, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8636")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 for Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4252")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7070")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 3.5 for Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.6000", test_version2:"2.0.50727.6420")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7070")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ##.NET Framework 3.5 for Windows 8.1 and Windows Server 2012 R2:
      if((hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8008")||
          version_in_range(version:dllVer, test_version:"2.0.50727.8600", test_version2:"2.0.50727.8614")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 3.5.1 for Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5484")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7070")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 4 on Windows Server 2003, Windows Vista,
      if((hotfix_check_sp(win2003:3, winVista:3, win2008:3, win7:2, win7x64:2, win2008r2:2) > 0) &&
        (version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1025")||
         version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2044")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    } ## mscorlib.dll - END
  }
}

key2 = "SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\";
foreach item (registry_enum_keys(key:key2))
{
  path = registry_get_sz(key:key2 + item, item:"All Assemblies In");
  if(path)
  {
    dllVer = fetch_file_version(sysPath:path, file_name:"system.identitymodel.dll");
    if(dllVer)
    {
      ## .NET Framework 3.0 Service Pack 2 for Windows Server 2003 Service Pack 2
      if((hotfix_check_sp(win2003:3, win2003x64:3) > 0) &&
       (version_in_range(version:dllVer, test_version:"3.0.4506.4000", test_version2:"3.0.4506.4067")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ##.NET Framework 3.5 for Windows 8.1 and Windows Server 2012 R2
      if((hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"3.0.4506.8000", test_version2:"3.0.4506.8001")||
          version_in_range(version:dllVer, test_version:"3.0.4506.8600", test_version2:"3.0.4506.8634")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 3.5 for Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"3.0.4506.6400", test_version2:"3.0.4506.6414")||
          version_in_range(version:dllVer, test_version:"3.0.4506.8600", test_version2:"3.0.4506.8634")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 3.5.1 for Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"3.0.4506.5400", test_version2:"3.0.4506.5462")||
          version_in_range(version:dllVer, test_version:"3.0.4506.8000", test_version2:"3.0.4506.8634")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 3.0 Service Pack 2 for Windows Vista Service Pack 2 and
      ##  Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"3.0.4506.4200", test_version2:"3.0.4506.4221")||
          version_in_range(version:dllVer, test_version:"3.0.4506.8600", test_version2:"3.0.4506.8634")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## NET Framework 4.5, the .NET Framework 4.5.1, and the .NET Framework 4.5.2 for Windows Vista SP2,
      ##  Windows Server 2008 SP2, Windows 7 SP1, and Windows Server 2008 R2 SP1
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34233")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 4.5, the .NET Framework 4.5.1, and the .NET Framework 4.5.2
      ## for Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34229") ||
          version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36240")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 4.5.1 and the .NET Framework 4.5.2 for Windows 8.1, and Windows Server 2012 R2
      if((hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34229") ||
          version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36240")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
