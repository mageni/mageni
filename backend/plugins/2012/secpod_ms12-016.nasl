###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework and Microsoft Silverlight Remote Code Execution Vulnerabilities (2651026)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902811");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-0014", "CVE-2012-0015");
  script_bugtraq_id(51938, 51940);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-02-15 10:10:10 +0530 (Wed, 15 Feb 2012)");
  script_name("Microsoft .NET Framework and Microsoft Silverlight Remote Code Execution Vulnerabilities (2651026)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48030");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2651026");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026681");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-016");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "gb_ms_silverlight_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attacker to execute arbitrary code within
  the context of the affected application. Failed exploit attempts will likely
  result in a denial-of-service condition.");

  script_tag(name:"affected", value:"Microsoft Silverlight 4.0

  Microsoft .NET Framework 4.0

  Microsoft .NET Framework 3.5.1

  Microsoft .NET Framework 2.0 Service Pack 2");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An unspecified error when handling un-managed objects can be exploited via
    a specially crafted XAML Browser Application (XBAP).

  - An error when calculating certain buffer lengths can be exploited to corrupt
    memory via a specially crafted XAML Browser Application (XBAP).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-016.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

if( infos = get_app_version_and_location( cpe:"cpe:/a:microsoft:silverlight", exit_no_version:FALSE ) ) {
  mslVers = infos['version'];
  mslPath = infos['location'];

  if( mslVers ) {
    if( version_is_less( version:mslVers, test_version:"4.1.10111" ) ) {
      report = report_fixed_ver( installed_version:mslVers, fixed_version:"4.1.10111", install_path:mslPath );
      security_message( port:0, data:report );
      exit( 0 );
    }
  }
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
    dllVer = fetch_file_version(sysPath:path, file_name:"System.dll");
    if(dllVer)
    {
      ## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, Windows 7
      if((hotfix_missing(name:"2633870") == 1))
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.000", test_version2:"4.0.30319.257")||
           version_in_range(version:dllVer, test_version:"4.0.30319.500", test_version2:"4.0.30319.522"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      ## .NET Framework 3.5.1 on Windows 7
      if(((hotfix_missing(name:"2633873") == 1) ||
         (hotfix_missing(name:"2633879") == 1)) && (hotfix_check_sp(win7:2) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4967")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5452")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5600", test_version2:"2.0.50727.5702"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_missing(name:"2633874") == 1) &&
         (hotfix_check_sp(winVista:3, win2008:3) > 0))
     {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4219")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5600", test_version2:"2.0.50727.5702"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows XP and Windows Server 2003
      if((hotfix_missing(name:"2633880") == 1) &&
         (hotfix_check_sp(xp:4, win2003:3) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3630")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5600", test_version2:"2.0.50727.5703"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}

exit( 99 );