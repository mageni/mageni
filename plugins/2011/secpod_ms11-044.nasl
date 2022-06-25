###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Remote Code Execution Vulnerability (2538814)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902522");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-06-15 15:55:00 +0200 (Wed, 15 Jun 2011)");
  script_cve_id("CVE-2011-1271");
  script_bugtraq_id(47834);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerability (2538814)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44899/");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-044");
  script_xref(name:"URL", value:"http://stackoverflow.com/questions/2135509/bug-only-occurring-when-compile-optimization-enabled/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow context-dependent attackers to bypass
  intended access restrictions in opportunistic circumstances by leveraging
  a crafted application.");
  script_tag(name:"affected", value:"Microsoft .NET Framework 4.0
  Microsoft .NET Framework 3.5
  Microsoft .NET Framework 3.5.1
  Microsoft .NET Framework 3.5 Service Pack 1
  Microsoft .NET Framework 2.0 Service Pack 2
  Microsoft .NET Framework 2.0 Service Pack 1");
  script_tag(name:"insight", value:"The flaw is due to the JIT compiler, when IsJITOptimizerDisabled is
  false, does not properly handle expressions related to null strings, which
  allows context-dependent attackers to bypass intended access restrictions.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-044.");
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

## MS11-044 Hotfix
if((hotfix_missing(name:"2518870") == 0) || (hotfix_missing(name:"2518869") == 0) ||
   (hotfix_missing(name:"2518867") == 0) || (hotfix_missing(name:"2518863") == 0) ||
   (hotfix_missing(name:"2518864") == 0) || (hotfix_missing(name:"2530095") == 0) ||
   (hotfix_missing(name:"2518865") == 0) || (hotfix_missing(name:"2518866") == 0) ){
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
    dllVer = fetch_file_version(sysPath:path, file_name:"mscorlib.dll");
    if(dllVer)
    {
      if(hotfix_check_sp(xp:4, win2003:3) > 0)
      {
        ## .NET Framework 4.0  GDR 4.0.30319.235 , LDR 4.0.30319.454
        ## .NET Framework 3.5 Service Pack 1 and .NET Framework 2.0 Service Pack 2
        ##  GDR 2.0.50727.3623, LDR 2.0.50727.5662
        ## .NET Framework 3.5 GDR 4.0.30319.235 , LDR 4.0.30319.454
        if(version_in_range(version:dllVer, test_version:"4.0.30319.200", test_version2:"4.0.30319.234")||
           version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.453")||
           version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3622")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5661"))
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

       ## .NET Framework 4.0  GDR 4.0.30319.235 , LDR 4.0.30319.454
       ## .NET Framework 3.5  GDR 2.0.50727.1891, LDR 2.0.50727.1891
       ## .NET Framework 3.5 Service Pack 1 GDR 2.0.50727.3623, LDR 2.0.50727.5662
       if("Service Pack 1" >< SP)
       {
         if(version_in_range(version:dllVer, test_version:"4.0.30319.200", test_version2:"4.0.30319.234")||
            version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.453")||
            version_in_range(version:dllVer, test_version:"2.0.50727.1000", test_version2:"2.0.50727.1890")||
            version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3622")||
            version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5661"))
          {
            security_message( port: 0, data: "The target host was found to be vulnerable" );
            exit(0);
          }
        }

       ## .NET Framework 4.0  GDR 4.0.30319.235 , LDR 4.0.30319.454
       ## .NET Framework 3.5 Service Pack 1 GDR 2.0.50727.4214, LDR 2.0.50727.5662
       if("Service Pack 2" >< SP)
       {
         if(version_in_range(version:dllVer, test_version:"4.0.30319.200", test_version2:"4.0.30319.234")||
            version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.453")||
            version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4213") ||
            version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5661"))
         {
           security_message( port: 0, data: "The target host was found to be vulnerable" );
           exit(0);
         }
       }
     }

     ## .NET Framework 4.0   GDR 4.0.30319.235 , LDR 4.0.30319.454
     ## .NET Framework 3.5.1 GDR 2.0.50727.5446, LDR 2.0.50727.5662 on win7 SP1
     ## .NET Framework 3.5.1 GDR 2.0.50727.4961, LDR 2.0.50727.5662
     if(hotfix_check_sp(win7:2) > 0)
     {
      if(version_in_range(version:dllVer, test_version:"4.0.30319.200", test_version2:"4.0.30319.234")||
         version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.453")||
         version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5445")||
         version_in_range(version:dllVer, test_version:"2.0.50727.5600", test_version2:"2.0.50727.5661")||
         version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4960")){
         security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
    }
  }
}
