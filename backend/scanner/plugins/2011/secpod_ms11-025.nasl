###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Foundation Class (MFC) Library Remote Code Execution Vulnerability (2500212)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Updated by: Antu Sanadi <santu@secpod.com> on 2011-08-11
# - Updated the file version check according to Bulletin
#   revision V3.0 (June 14, 2011) and V4.0 (August 9, 2011)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900285");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_bugtraq_id(42811);
  script_cve_id("CVE-2010-3190");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Foundation Class (MFC) Library Remote Code Execution Vulnerability (2500212)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41212");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2565057");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS11-025.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_visual_prdts_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Microsoft/VisualStudio_or_VisualStudio.Net/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code which
  may result in memory corruption on the affected system.");

  script_tag(name:"affected", value:"Microsoft Visual Studio 2010

  Microsoft Visual Studio 2005 SP 1 and prior

  Microsoft Visual Studio 2008 SP 1 and prior

  Microsoft Visual Studio .NET 2003 SP 1 and prior");

  script_tag(name:"insight", value:"A flaw exists in the Microsoft Foundation Class (MFC) Library, when
  applications built using MFC incorrectly restrict the path used for loading external libraries.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-025.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## MS11-025 Hotfix check
if((hotfix_missing(name:"2538218") == 0)||(hotfix_missing(name:"2538241") == 0) ||
   (hotfix_missing(name:"2542054") == 0)||(hotfix_missing(name:"2565057") == 0)){
  exit(0);
}

visStudVer = get_kb_item("Microsoft/VisualStudio/Ver");

if(visStudVer && visStudVer =~ "^([89]|10)\.")
{
  studioPath = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\8.0", item:"InstallDir");
  if(studioPath){
    atlPath = studioPath - "\Common7\IDE" + "VC\redist\x86\Microsoft.VC80.ATL\atl80.dll";
  }
  else
  {
    studioPath = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\9.0", item:"InstallDir");
    if(studioPath){
      atlPath = studioPath - "\Common7\IDE" + "VC\redist\x86\Microsoft.VC90.ATL" + "\atl90.dll";
    }
    else
    {
      studioPath = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\10.0", item:"InstallDir");
      if(studioPath){
        atlPath = studioPath - "\Common7\IDE" + "VC\redist\x86\Microsoft.VC100.ATL\atl100.dll";
      }
    }
  }
}

if(atlPath)
{
  share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:atlPath);
  file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:atlPath);
  atlVer = GetVer(file:file, share:share);
  if(atlVer && atlVer =~ "^([89]|10)\.")
  {
    ## Visual Studio 2008 SP1 version 9.0 <  9.0.30729.6161 and
    ## Visual Studio 2010 version 10.0 < 10.0.30319.460
    ## Visual Studio 2010  SP1 10 < 10.0.40219.325
    if(version_in_range(version:atlVer, test_version:"8.0", test_version2:"8.0.50727.6194") ||
       version_in_range(version:atlVer, test_version:"9.0", test_version2:"9.0.30729.6160") ||
       version_in_range(version:atlVer, test_version:"10.0.30000.000",test_version2:"10.0.30319.459") ||
       version_in_range(version:atlVer, test_version:"10.0.40000.000",test_version2:"10.0.40219.324"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

if(hotfix_missing(name:"2465373") == 0){
  exit(0);
}

visStudNetVer = get_kb_item("Microsoft/VisualStudio.Net/Ver");

if(visStudNetVer && visStudNetVer =~ "^7\.")
{
  vsnfile1 = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup", item:"Install Path");
  if(!vsnfile1){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:vsnfile1);
  vsnfile2 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:vsnfile1 + "\atl71.dll");
  vsnetVer = GetVer(file:vsnfile2, share:share);

  if(vsnetVer && vsnetVer =~ "^7\.")
  {
    if(version_in_range(version:vsnetVer, test_version:"7.0", test_version2:"7.10.6118.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
