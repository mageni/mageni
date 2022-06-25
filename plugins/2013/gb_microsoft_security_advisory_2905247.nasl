###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft ASP.NET Insecure Site Configuration Vulnerability (2905247)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804038");
  script_version("2019-05-03T12:31:27+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-12-12 15:24:42 +0530 (Thu, 12 Dec 2013)");
  script_name("Microsoft ASP.NET Insecure Site Configuration Vulnerability (2905247)");
  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
advisory (2905247).");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Flaw is due to the view state that exists when Machine Authentication Code
(MAC) validation is disabled through configuration settings.");
  script_tag(name:"affected", value:"Microsoft .NET Framework versions 1.1, 2.0, 3.5, 3.5.1, 4.0, 4.5 and 4.5.1");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to use specially crafted
HTTP content to inject code to be run in the context of the service account
on the ASP.NET server.");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2905247");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/advisory/2905247");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Windows");
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
             win7x64:2, win2008:3, win2008r2:2, win8:1, win8_1:1, win8_1x64:1,
             win2012:1) <= 0){
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
    exeVer = fetch_file_version(sysPath:path, file_name:"aspnet_wp.exe");
    if(exeVer)
    {
      ## .NET Framework 4.5.1 on Windows 7 SP1 and Windows Server 2008 R2 SP 1
      ##  Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:exeVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18339")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 4.5.1 on Windows 7 SP1 and Windows Server 2008 R2 SP 1
      ##  Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:exeVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18441")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ##  .NET Framework 4.5.1 on Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win2012:1) > 0) &&
         (version_in_range(version:exeVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18446")||
          version_in_range(version:exeVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19452")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ##  .NET Framework 4.5.1 on Windows 8.1
      ##  Currently we are not supporting Windows 2012r2
      if((hotfix_check_sp(win8_1:1, win8_1x64:1) > 0) &&
         (version_in_range(version:exeVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34005")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 4.5 on Windows 7 SP1 and Windows Server 2008 R2 SP 1
      ##  Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:exeVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18060")||
          version_in_range(version:exeVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19125")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 4.5 on Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win2012:1) > 0) &&
         (version_in_range(version:exeVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18061")||
          version_in_range(version:exeVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19126")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008,
      ##  Windows 7 and and Windows Server 2008 R2
      if(version_in_range(version:exeVer, test_version:"4.0.30319.0000", test_version2:"4.0.30319.1016")||
         version_in_range(version:exeVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2027"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 3.5.1 on Windows 7 and Windows Server 2008 R2
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:exeVer, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5476")||
          version_in_range(version:exeVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7040")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ##  .NET Framework 3.5 on Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win2012:1) > 0) &&
         (version_in_range(version:exeVer, test_version:"2.0.50727.6000", test_version2:"2.0.50727.6411")||
          version_in_range(version:exeVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7040")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ##  .NET Framework 3.5 on Windows 8.1
      ##  Currently we are not supporting Windows 2012r2
      if((hotfix_check_sp(win8_1:1, win8_1x64:1) > 0) &&
         (version_in_range(version:exeVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7999")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows XP and Windows Server 2003
      if((hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0) &&
         (version_in_range(version:exeVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3656")||
          version_in_range(version:exeVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7042")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(winVista:3, win2008:3) > 0) &&
         (version_in_range(version:exeVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4246")||
          version_in_range(version:exeVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7040")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 1.1 Service Pack 1 on Windows Server 2003 sp2 x86
      if((hotfix_check_sp(win2003:3) > 0) &&
         (version_in_range(version:exeVer, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2503")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
