###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Web Components ActiveX Control Code Execution Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Update to MS09-043 Bulletin (957638)
#   - By Sharath S <sharaths@secpod.com> On 2009-08-13
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
  script_oid("1.3.6.1.4.1.25623.1.0.800845");
  script_version("2019-05-03T08:55:39+0000");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1136", "CVE-2009-0562", "CVE-2009-2496", "CVE-2009-1534");
  script_bugtraq_id(35642, 35990, 35991, 35992);
  script_name("Microsoft Office Web Components ActiveX Control Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35800/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/957638");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1867");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/973472.mspx");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms09-043.mspx");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code which may
  result in a Denial of Service condition on the affected system.");

  script_tag(name:"affected", value:"Microsoft Office XP/2003 SP 3 and prior

  Microsoft Visual Studio .NET 2003 SP 1 and prior

  Microsoft Office XP/2003 Web Components SP 3 and prior

  Microsoft ISA Server 2004 Standard/Enterprise Edition SP 3 and prior

  Microsoft ISA Server 2006 Standard/Enterprise Edition SP 1 and prior

  Microsoft Office 2003 Web Components for 2007 Microsoft Office system SP 1");

  script_tag(name:"insight", value:"- Error exists in the OWC10.Spreadsheet ActiveX control that can be
  exploited via specially crafted parameters passed to the 'msDataSourceObject()' method.

  - Error occurs when loading and unloading the OWC10 ActiveX control.

  - Error exists in the OWC10.Spreadsheet ActiveX control related to the
  'BorderAround()' method via accessing certain methods in a specific order.

  - A boundary error in the Office Web Components ActiveX control which can be
  exploited to cause a buffer overflow.");

  script_tag(name:"summary", value:"This host is installed with Microsoft Office Web Components ActiveX Control
  and is prone to code execution vulnerability.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.

  As a workaround set the killbit for the following CLSIDs:

  {0002E541-0000-0000-C000-000000000046}, {0002E559-0000-0000-C000-000000000046},
  {0002E55B-0000-0000-C000-000000000046}");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

function getWebCmpntsVer(webpath, webfile)
{
  webdllpath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                               item:"ProgramFilesDir");
  if(webdllpath == NULL){
    return NULL;
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:webdllpath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                      string:webdllpath + webpath + webfile);

  webdllVer = GetVer(share:share, file:file);

  if(webdllVer == NULL){
    return NULL;
  }

  return webdllVer;
}


# MS09-043 Hotfix check
if((hotfix_missing(name:"947320") == 0)||(hotfix_missing(name:"947319") == 0)||
   (hotfix_missing(name:"947318") == 0)||(hotfix_missing(name:"947826") == 0)||
   (hotfix_missing(name:"969172") == 0)){
  exit(0);
}

if(registry_key_exists(key:"SOFTWARE\Microsoft\Office"))
{
  # Path for OWC10.dll file
  dllPath = "\Common Files\Microsoft Shared\Web Components";

  # Office XP Web Components for Office XP/2003
  dllVer = getWebCmpntsVer(webpath:dllPath, webfile:"\10\OWC10.DLL");

  if(dllVer == NULL)
  {
    # Office 2003 Web Components for Office 2003/2007
    dllVer = getWebCmpntsVer(webpath:dllPath, webfile:"\11\OWC11.DLL");
  }

  if(dllVer != NULL)
  {
    # Office XP   Web Components 10.0 < 10.0.6854.0 in Office XP/2003
    # Office 2003 Web Components 11.0 < 11.0.8304.0 in Office 2003
    # Office 2003 Web Components 12.0 < 12.0.6502.5000 for Office 2007
    if(version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.6853.0")||
       version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.8303.0")||
       version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6502.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

if(registry_key_exists(key:"SOFTWARE\Microsoft\Fpc"))
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
  if(registry_key_exists(key:key))
  {
  foreach item (registry_enum_keys(key:key))
  {
    isaName = registry_get_sz(key:key + item, item:"DisplayName");
    if("Microsoft ISA Server 2006 Service Pack 1" >< isaName ||
       "Microsoft ISA Server 2004 Service Pack 3" >< isaName)
    {
      if(is_killbit_set(clsid:"{0002E541-0000-0000-C000-000000000046}") == 0)
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      else if(is_killbit_set(clsid:"{0002E559-0000-0000-C000-000000000046}") == 0)
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      else if(is_killbit_set(clsid:"{0002E55B-0000-0000-C000-000000000046}") == 0)
       security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
    else if(isaName =~ "Microsoft ISA Server [2004|2006]")
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
  }
}

# Microsoft Visual Studio .NET 2003 SP1
if(registry_key_exists(key:"SOFTWARE\Microsoft\VisualStudio\7.0"))
{
  dllVer = getWebCmpntsVer(webpath:"\Microsoft Office\Office10",
                           webfile:"\MSOWC.DLL");

  if(dllVer != NULL)
  {
    # Msowc.dll version 9.0 < 9.0.0.8977 for Visual Studio .NET 2003 SP1
    if(version_in_range(version:dllVer, test_version:"9.0",
                                       test_version2:"9.0.0.8976")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
