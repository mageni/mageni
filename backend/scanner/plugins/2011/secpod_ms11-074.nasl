###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Multiple Privilege Escalation Vulnerabilities (2451858)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902625");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_cve_id("CVE-2011-0653", "CVE-2011-1252", "CVE-2011-1890", "CVE-2011-1891",
                "CVE-2011-1892", "CVE-2011-1893");
  script_bugtraq_id(49002, 48199, 49010, 49005, 49511, 49004);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Microsoft SharePoint Multiple Privilege Escalation Vulnerabilities (2451858)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2451858");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms11-074.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code on the system with elevated privileges via a specially crafted URL or
  or a crafted Web site.");
  script_tag(name:"affected", value:"Microsoft Windows SharePoint Services 2.0
  Microsoft Groove 2007 Service Pack 2 and prior
  Microsoft Office SharePoint Server 2007 Service Pack 2
  Microsoft Windows SharePoint Services 3.0 Service Pack 2
  Microsoft Office SharePoint Workspace 2010 Service Pack 1 and prior");
  script_tag(name:"insight", value:"Multiple flaws are due to the way Microsoft SharePoint validates and
  sanitizes user input, parses malicious XML and XSL files and handles
  script contained inside of specific request parameter.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-074.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


## MS11-074 Hotfix (2451858)

if(hotfix_missing(name:"2451858") == 0){
#  exit(0);
}

## Microsoft Groove 2007
exeVer = get_kb_item("SMB/Office/Groove/Version");
if(exeVer =~ "^12\..*")
{
  if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6552.4999"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## Microsoft SharePoint Server 2007
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(registry_key_exists(key:key))
{
  foreach item (registry_enum_keys(key:key))
  {
    appName = registry_get_sz(item:"DisplayName", key:key + item);
    if("Microsoft Office SharePoint Server 2007" >< appName)
    {
      dllPath =  registry_get_sz(item:"BinPath",
                            key:"SOFTWARE\Microsoft\Office Server\12.0");
      vers  = fetch_file_version(sysPath:dllPath, file_name:"Microsoft.sharepoint.publishing.dll");
      if(vers)
      {
         if(version_is_less(version:vers, test_version:"12.0.6562.5000"))
         {
           security_message( port: 0, data: "The target host was found to be vulnerable" );
           exit(0);
         }
      }
    }
  }
}

## Microsoft Windows SharePoint Services
if(registry_key_exists(key:key))
{
  foreach item (registry_enum_keys(key:key))
  {
    srvcName = registry_get_sz(item:"DisplayName", key:key + item);
    if("Microsoft Windows SharePoint Services" >< srvcName)
    {
      dllPath =  registry_get_sz(item:"SharedFilesDir",
                              key:"SOFTWARE\Microsoft\Shared Tools");

    if(dllPath)
    {
      dllPath1 = dllPath + "web server extensions\12\BIN";
      dllPath2 = dllPath + "web server extensions\60\BIN";
      dllVer1  = fetch_file_version(sysPath:dllPath1, file_name:"Onetutil.dll");
      dllVer2  = fetch_file_version(sysPath:dllPath2, file_name:"Onetutil.dll");

      if(dllVer1 || dllVer2)
      {
        if(version_in_range(version:dllVer2, test_version:"11.0", test_version2:"11.0.8339.0") ||
           version_in_range(version:dllVer1, test_version:"12.0", test_version2:"12.0.6565.5000"))
        {
           security_message( port: 0, data: "The target host was found to be vulnerable" );
           exit(0);
        }
      }
    }
  }
}
}


## Microsoft SharePoint Workspace 2010
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office14.GROOVER";
if(!registry_key_exists(key:key)) {
    exit(0);
}

worksName =  registry_get_sz(item:"DisplayName", key:key);
if("Microsoft SharePoint Workspace 2010" >< worksName)
{
  worksPath = registry_get_sz(key:key,item:"InstallLocation");
  worksPath += "Office14";
  worksVer  = fetch_file_version(sysPath:worksPath, file_name:"GROOVE.exe");
  if(worksVer && worksVer =~ "^14\..*")
  {
    if(version_is_less(version:worksVer, test_version:"14.0.6106.5000"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
