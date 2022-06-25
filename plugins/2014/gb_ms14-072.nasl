###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Privilege Elevation Vulnerability (3005210)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804791");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2014-4149");
  script_bugtraq_id(70979);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-11-12 11:23:27 +0530 (Wed, 12 Nov 2014)");
  script_name("Microsoft .NET Framework Privilege Elevation Vulnerability (3005210)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS14-072.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws exists in the way that .NET Framework
  handles TypeFilterLevel checks for some malformed objects.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass certain security restrictions.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 1.1, 2.0, 3.5,
  3.5.1, 4.0, 4.5, 4.5.1 and 4.5.2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59979");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3005210");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-072");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2,
                   win2008:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
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
    dllVer = fetch_file_version(sysPath:path, file_name:"system.runtime.remoting.dll");
    if(dllVer)
    {
      ## .NET Framework 1.1 Service Pack 1 on Windows Server 2003 Service Pack 2 32-bit Edition
      if((hotfix_check_sp(win2003:3, win2003x64:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2510")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Server 2003
      if((hotfix_check_sp(win2003:3, win2003x64:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3663")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.8641")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4254")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.8640")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ##.NET Framework 3.5 on Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.6000", test_version2:"2.0.50727.6423")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.8640")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 3.5 on Windows 8.1 and Windows Server 2012 R2
      if((hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0) &&
       (version_in_range(version:dllVer, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8011")||
        version_in_range(version:dllVer, test_version:"2.0.50727.8600", test_version2:"2.0.50727.8640")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ##.NET Framework 3.5.1 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1: May 13, 2014
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5487")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.8640")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 4 on Windows Server 2003, Windows Vista, Windows Server 2008,
      if((hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2) > 0) &&
        (version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1029")||
         version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2048")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 4.5, 4.5.1, and 4.5.2 on Windows 7 Service Pack 1, Windows Server 2008 R2 Service Pack 1,
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34244")||
          version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36256")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 4.5, 4.5.1, and 4.5.2 on Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34242")||
          version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36254")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }


     ## .NET Framework 4.5.1 and 4.5.2 on Windows 8.1 and Windows Server 2012 R2
     if((hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0) &&
       (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34242")||
        version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36254")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
