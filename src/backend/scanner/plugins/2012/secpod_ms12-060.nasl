###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Common Controls Remote Code Execution Vulnerability (2720573)
#
# Authors:
# Veerendra G G <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.901211");
  script_version("2019-05-03T12:31:27+0000");
  script_bugtraq_id(54948);
  script_cve_id("CVE-2012-1856");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-08-15 09:05:46 +0530 (Wed, 15 Aug 2012)");
  script_name("Microsoft Windows Common Controls Remote Code Execution Vulnerability (2720573)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50247");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-060");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary code
  within the context of the application.");

  script_tag(name:"affected", value:"Microsoft Visual Basic 6.0

  Microsoft Commerce Server 2009

  Microsoft SQL Server 2000 Service Pack 4

  Microsoft SQL Server 2005 Service Pack 4

  Microsoft SQL Server 2008 Service Pack 2

  Microsoft SQL Server 2008 Service Pack 3

  Microsoft Visual FoxPro 8.0 Service Pack 1

  Microsoft Visual FoxPro 9.0 Service Pack 2

  Microsoft Commerce Server 2002 Service Pack 4

  Microsoft Commerce Server 2007 Service Pack 2

  Microsoft Office 2003 Service Pack 3 and prior

  Microsoft Office 2007 Service Pack 3 and prior

  Microsoft Office 2010 Service Pack 1 and prior

  Microsoft Host Integration Server 2004 Service Pack 1

  Microsoft SQL Server 2000 Analysis Services Service Pack 4

  Microsoft SQL Server 2005 Express Edition with Advanced Services Service Pack 4");

  script_tag(name:"insight", value:"The flaw is due to an error within the TabStrip ActiveX control
  in MSCOMCTL.OCX file and can be exploited to execute arbitrary code.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-060.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

officeVer = get_kb_item("MS/Office/Ver");

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mscomctl.Ocx");
if(sysVer)
{
  if(officeVer && officeVer =~ "^1[124]\.")
  {
    if(version_is_less(version:sysVer, test_version:"6.1.98.34"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  key = "SOFTWARE\Microsoft\Visual Basic\6.0";
  if(registry_key_exists(key:key))
  {
    if(version_is_less(version:sysVer, test_version:"6.1.98.34"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  foreach ver (make_list("8.0", "9.0"))
  {
    key = "SOFTWARE\Microsoft\VisualFoxPro\" + ver;
    if(registry_key_exists(key:key))
    {
      if(version_is_less(version:sysVer, test_version:"6.1.98.34"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft SQL Server 2000 Analysis Services";
if(registry_key_exists(key:key))
{
  path = registry_get_sz(key:key, item:"InstallLocation");
  dllVer = fetch_file_version(sysPath:path, file_name:"bin\msmdctr80.dll");
  if(dllVer)
  {
    if(version_is_less(version:dllVer, test_version:"8.0.2304.0"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft SQL Server 2000";
if(registry_key_exists(key:key))
{
  path = registry_get_sz(key:key, item:"InstallLocation");
  exeVer = fetch_file_version(sysPath:path, file_name:"Binn\sqlservr.exe");
  if(exeVer)
  {
    if(version_is_less(version:exeVer, test_version:"2000.80.2066.0") ||
       version_in_range(version:exeVer, test_version:"2000.80.2300.0", test_version2:"2000.80.2304.0"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}


key = "SOFTWARE\Microsoft\Host Integration Server\6.0";
if(registry_key_exists(key:key))
{
  prdName = registry_get_sz(key:key, item:"ProductName");
  if("Microsoft Host Integration Server 2004" >< prdName)
  {
    dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\comctl32.Ocx");
    if(dllVer)
    {
      if(version_is_less(version:dllVer, test_version:"6.0.98.34"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

keys = make_list("SOFTWARE\Microsoft\Commerce Server",
                 "SOFTWARE\Microsoft\Commerce Server 2007",
                 "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"+
                 "\Microsoft Commerce Server 2009");

foreach key (keys)
{
  if(registry_key_exists(key:key))
  {
    dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\mscomctl.ocx");
    if(dllVer)
    {
      if(version_is_less(version:dllVer, test_version:"6.1.98.34"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
