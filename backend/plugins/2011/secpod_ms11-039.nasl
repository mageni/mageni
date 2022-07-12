###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework and Silverlight Remote Code Execution Vulnerability (2514842)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902523");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-06-15 15:55:00 +0200 (Wed, 15 Jun 2011)");
  script_cve_id("CVE-2011-0664");
  script_bugtraq_id(48212);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft .NET Framework and Silverlight Remote Code Execution Vulnerability (2514842)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "gb_ms_silverlight_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attacker to execute arbitrary code within
  the context of the application.");
  script_tag(name:"affected", value:"Microsoft Silverlight 4.0

  Microsoft .NET Framework 4.0

  Microsoft .NET Framework 3.5

  Microsoft .NET Framework 3.5.1

  Microsoft .NET Framework 3.5 Service Pack 1

  Microsoft .NET Framework 2.0 Service Pack 2

  Microsoft .NET Framework 2.0 Service Pack 1");
  script_tag(name:"insight", value:"The flaw is due to an input validation error when passing values to
  trusted APIs. This can be exploited to access memory in an unsafe manner via
  a specially crafted XAML Browser Application or Silverlight application.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-039.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44841");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-039");
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

## MS11-039 Hotfix
if((hotfix_missing(name:"2478663") == 0) || (hotfix_missing(name:"2478662") == 0) ||
   (hotfix_missing(name:"2478661") == 0) || (hotfix_missing(name:"2478660") == 0) ||
   (hotfix_missing(name:"2478659") == 0) || (hotfix_missing(name:"2478658") == 0) ||
   (hotfix_missing(name:"2478656") == 0) || (hotfix_missing(name:"2478657") == 0) ){
  exit(0);
}

if( infos = get_app_version_and_location( cpe:"cpe:/a:microsoft:silverlight", exit_no_version:FALSE ) ) {
  mslVers = infos['version'];
  mslPath = infos['location'];

  if( mslVers ) {
    if( version_is_less( version:mslVers, test_version:"4.0.60531.0" ) ) {
      report = report_fixed_ver( installed_version:mslVers, fixed_version:"4.0.60531.0", install_path:mslPath );
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
  if("\Microsoft.NET\Framework" >< path)
  {
    dllVer = fetch_file_version(sysPath:path, file_name:"System.dll");
    if(dllVer)
    {
      if(hotfix_check_sp(xp:4, win2003:3) > 0)
      {
        ## .NET Framework 4.0  GDR 4.0.30319.232, LDR 4.0.30319.447
        ## .NET Framework 3.5 Service Pack 1 and .NET Framework 2.0 Service Pack 2
        ##  GDR 2.0.50727.3620, LDR 2.0.50727.5071
        ## .NET Framework 3.5 GDR=LDR 2.0.50727.1889
        if(version_in_range(version:dllVer, test_version:"4.0.30319.200", test_version2:"4.0.30319.231")||
           version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.446")||
           version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3619")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5070")||
           version_in_range(version:dllVer, test_version:"2.0.50727.1000", test_version2:"2.0.50727.1888"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        SP = get_kb_item("SMB/WinVista/ServicePack");

        if(!SP) {
          SP = get_kb_item("SMB/Win2008/ServicePack");
        }
        ## .NET Framework 4.0  GDR 4.0.30319.232, , LDR 4.0.30319.447
        ## .NET Framework 3.5  GDR 2.0.50727.1889, LDR 2.0.50727.1889
        ## .NET Framework 3.5 Service Pack 1 GDR 2.0.50727.3620, LDR 2.0.50727.5071
        if("Service Pack 1" >< SP)
        {
          if(version_in_range(version:dllVer, test_version:"4.0.30319.200", test_version2:"4.0.30319.231")||
             version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.446")||
             version_in_range(version:dllVer, test_version:"2.0.50727.1000", test_version2:"2.0.50727.1888")||
             version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3619")||
             version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5070"))
          {
            security_message( port: 0, data: "The target host was found to be vulnerable" );
            exit(0);
          }
        }

        ## .NET Framework 4.0  GDR 4.0.30319.232, , LDR 4.0.30319.447
        ## .NET Framework 3.5 Service Pack 1 GDR 2.0.50727.4212, LDR 2.0.50727.5071
        if("Service Pack 2" >< SP)
        {
          if(version_in_range(version:dllVer, test_version:"4.0.30319.200", test_version2:"4.0.30319.231")||
             version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.446")||
             version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4211") ||
             version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5070"))
          {
            security_message( port: 0, data: "The target host was found to be vulnerable" );
            exit(0);
          }
        }
      }

      ## .NET Framework 4.0  GDR 4.0.30319.232, , LDR 4.0.30319.447
      ## .NET Framework 3.5.1 GDR 2.0.50727.5442, LDR 2.0.50727.5650 on win7 SP1
      ## .NET Framework 3.5.1 2.0.50727.4957, LDR 2.0.50727.5071
      if(hotfix_check_sp(win7:2) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.200", test_version2:"4.0.30319.231")||
           version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.446")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5441")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5600", test_version2:"2.0.50727.5649")||
           version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4956")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5070")){
         security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
    }
  }
}

exit(99);