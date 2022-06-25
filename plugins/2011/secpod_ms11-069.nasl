###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Information Disclosure Vulnerability (2567951)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902551");
  script_version("2019-05-03T11:57:32+0000");
  script_tag(name:"last_modification", value:"2019-05-03 11:57:32 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)");
  script_cve_id("CVE-2011-1978");
  script_bugtraq_id(48991);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Microsoft .NET Framework Information Disclosure Vulnerability (2567951)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45517");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2567951");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-069");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attacker to bypass certain security
  restrictions or gain knowledge of sensitive information.");
  script_tag(name:"affected", value:"Microsoft .NET Framework 4.0

  Microsoft .NET Framework 3.5.1

  Microsoft .NET Framework 2.0 Service Pack 2");
  script_tag(name:"insight", value:"The flaw is due to an error when validating the trust level within
  the System.Net.Sockets namespace and can be exploited to bypass CAS (Code
  Access Security) restrictions or disclose information via a specially
  crafted web page viewed using a browser that supports XBAPs (XAML Browser
  Applications).");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-069.");
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

## MS11-069 Hotfix
if((hotfix_missing(name:"2539636") == 0) || (hotfix_missing(name:"2539635") == 0) ||
   (hotfix_missing(name:"2539634") == 0) || (hotfix_missing(name:"2539633") == 0) ||
   (hotfix_missing(name:"2539631") == 0) ){
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
    dllVer = fetch_file_version(sysPath:path, file_name:"System.dll");
    if(dllVer)
    {
      if(hotfix_check_sp(xp:4, win2003:3) > 0)
      {
        ## .NET Framework 4.0     GDR 4.0.30319.236,  LDR 4.0.30319.463
        ## .NET Framework 2.0 SP2 GDR 2.0.50727.3624, LDR 2.0.50727.5668
        if(version_in_range(version:dllVer, test_version:"4.0.30319.000", test_version2:"4.0.30319.235")||
           version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.462")||
           version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3623")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5667"))
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

        ## .NET Framework 4.0     GDR 4.0.30319.236,  LDR 4.0.30319.463
        ## .NET Framework 2.0 SP2 GDR 2.0.50727.4215, LDR 2.0.50727.5668
        if("Service Pack 2" >< SP)
        {
          if(version_in_range(version:dllVer, test_version:"4.0.30319.000", test_version2:"4.0.30319.235")||
             version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.462")||
             version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4214")||
             version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5667"))
          {
            security_message( port: 0, data: "The target host was found to be vulnerable" );
            exit(0);
          }
        }
      }

      ## .NET Framework 4.0  GDR 4.0.30319.236, , LDR 4.0.30319.463
      ## .NET Framework 3.5.1 GDR 2.0.50727.5447, LDR 2.0.50727.5668 on win7 SP1
      ## .NET Framework 3.5.1 2.0.50727.4962, LDR 2.0.50727.5668 on win7
      if(hotfix_check_sp(win7:2) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.000", test_version2:"4.0.30319.235")||
           version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.462")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5446")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5600", test_version2:"2.0.50727.5667")||
           version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4961")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
      }
    }
  }
}
