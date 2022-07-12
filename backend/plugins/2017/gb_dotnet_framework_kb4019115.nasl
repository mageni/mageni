###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Security Bypass Vulnerability (4019115)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811036");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0248");
  script_bugtraq_id(98117);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-05-11 10:37:20 +0530 (Thu, 11 May 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft .NET Framework Security Bypass Vulnerability (4019115)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4019115");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists when Microsoft .NET Framework
  (and .NET Core) components do not completely validate certificates.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions and perform unauthorized
  actions.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 2.0 Service Pack 2
  Microsoft .NET Framework 4.5.2
  Microsoft .NET Framework 4.6");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4019115");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4019115");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2008:3, win2008x64:3, win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  dotPath = registry_get_sz(key:key + item, item:"Path");
  if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
  {
    ## .NET Framework 2.0 Service Pack 2 on Windows Server 2008 Service Pack 2
    ## https://support.microsoft.com/en-us/help/4014502
    if(hotfix_check_sp(win2008:3, win2008x64:3) > 0)
    {
      sysdllVer = fetch_file_version(sysPath:dotPath, file_name:"System.data.dll");
      if(sysdllVer)
      {
        if(version_in_range(version:sysdllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.8761"))
        {
          report = 'File checked:     ' + dotPath + "\System.data.dll" + '\n' +
                   'File version:     ' + sysdllVer  + '\n' +
                   'Vulnerable range:  2.0.50727.5700 - 2.0.50727.8761\n' ;
          security_message(data:report);
          exit(0);
        }
      }
    }

    sysdllVer = fetch_file_version(sysPath:dotPath, file_name:"system.management.dll");
    if(sysdllVer)
    {
      ## .NET Framework 4.5.2 on Windows Server 2008 Service Pack 2,
      ## https://support.microsoft.com/en-us/help/4014514
      if(version_in_range(version:sysdllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.36391"))
      {
        VULN = TRUE ;
        vulnerable_range = "4.0.30319.30000 - 4.0.30319.36391";
      }

      ## .NET Framework 4.6 and 4.6.1 for Windows 7 SP1 and Windows Server 2008 R2 SP1 and
      ## the .NET Framework 4.6 for Windows Server 2008 SP2
      ## https://support.microsoft.com/en-us/help/4014511
      else if(version_in_range(version:sysdllVer, test_version:"4.6", test_version2:"4.6.1098"))
      {
        VULN = TRUE ;
        vulnerable_range = "4.6 - 4.6.1098";
      }

      if(VULN)
      {
        report = 'File checked:     ' + dotPath + "\system.management.dll" + '\n' +
                 'File version:     ' + sysdllVer  + '\n' +
                 'Vulnerable range: ' + vulnerable_range + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}
