###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Privilege Elevation Vulnerabilities (2028554)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902069");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-06-09 17:19:57 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-1257", "CVE-2010-1264");
  script_bugtraq_id(40409, 40559);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Microsoft SharePoint Privilege Elevation Vulnerabilities (2028554)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to attackers to gain knowledge
  of sensitive information or cause a denial of service.");
  script_tag(name:"affected", value:"Microsoft Office InfoPath 2003 Service Pack 3
  Microsoft Office InfoPath 2007 Service Pack 1/2
  Microsoft Office SharePoint Server 2007 Service Pack 2
  Microsoft Windows SharePoint Services 3.0 Service Pack 1/2");
  script_tag(name:"insight", value:"The flaws are due to,

  - An error within the 'help.aspx' page, which could allow cross-site scripting
    attacks.

  - An error in the way that the 'toStaticHTML' API sanitizes HTML on a SharePoint
    site, which could allow cross-site scripting attacks.

  - An error when handling specially crafted requests sent to the Help page, which
    could allow attackers to cause a denial of service.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-039.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/979445");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/983444");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/980923");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/979441");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-039");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-039.mspx");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

# MS10-039 Hotfix check
if((hotfix_missing(name:"980923") == 0) && (hotfix_missing(name:"979441") == 0) &&
   (hotfix_missing(name:"979445") == 0)){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(item:"DisplayName", key:key + item);
  if("Microsoft Office SharePoint Server 2007" >< appName)
  {
    dllPath =  registry_get_sz(item:"SharedFilesDir",
                          key:"SOFTWARE\Microsoft\Shared Tools");

    dllPath += "web server extensions\12\ISAPI\Microsoft.Office.Server.dll";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

    vers = GetVer(file:file, share:share);
    if(vers)
    {
      if(version_is_less(version:vers, test_version:"12.0.6524.5000"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

list = make_list("11.0","12.0");
foreach i (list)
{
  exePath =registry_get_sz(key:"SOFTWARE\Microsoft\Office\" + i + "\Common\InstallRoot",
                                 item:"Path");
  if(exePath)
  {
    exeVer = fetch_file_version(sysPath:exePath, file_name:"INFOPATH.EXE");
    if(exeVer)
    {
      if(version_in_range(version:exeVer, test_versio:"11.0", test_version2:"11.0.8232.0") ||
         version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6529.4999"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

## Microsoft Windows SharePoint Services
dllPath =  registry_get_sz(item:"SharedFilesDir",
                          key:"SOFTWARE\Microsoft\Shared Tools");

if(dllPath)
{
  dllPath += "web server extensions\12\BIN\bpa.common.dll";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);
  dllVer = GetVer(file:file, share:share);
  if(dllVer)
  {
    if(version_is_less(version:dllVer, test_version:"8.0.669.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
