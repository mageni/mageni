###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2489283)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.902411");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-0655", "CVE-2011-0656", "CVE-2011-0976");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2489283)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2464617");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2464588");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2464594");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2464623");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2519975");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2519984");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS11-022.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/PowerPnt/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a malicious PPT file.");

  script_tag(name:"affected", value:"Microsoft PowerPoint 2010

  Microsoft PowerPoint Viewer 2010

  Microsoft PowerPoint 2002 Service Pack 3

  Microsoft PowerPoint 2003 Service Pack 3

  Microsoft PowerPoint 2007 Service Pack 2

  Microsoft PowerPoint Viewer 2007 Service Pack 2");

  script_tag(name:"insight", value:"The flaws are caused by errors related to floating point techno-color time bandit,
  persist directory and OfficeArt atoms, which could be exploited by attackers to
  execute arbitrary code by tricking a user into opening a specially crafted PowerPoint file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-022.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms11-022.mspx");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

if(!officeVer || officeVer !~ "^1[0124]\."){
  exit(0);
}

pptVer = get_kb_item("SMB/Office/PowerPnt/Version");
if(pptVer && pptVer =~ "^1[0124]\.")
{
  if(version_in_range(version:pptVer, test_version:"10.0", test_version2:"10.0.6867.0") ||
     version_in_range(version:pptVer, test_version:"11.0", test_version2:"11.0.8333.0") ||
     version_in_range(version:pptVer, test_version:"12.0", test_version2:"12.0.6545.4999"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# Office Power Point for 2010
if(registry_key_exists(key:"SOFTWARE\Microsoft\Office"))
{
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
  if(sysPath)
  {
    dllVer = fetch_file_version(sysPath:sysPath, file_name:"Microsoft Office\Office14\ppcore.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.5136.5002"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

ppviewVer = get_kb_item("SMB/Office/PPView/Version");
if(ppviewVer && ppviewVer =~ "^1[24]\.")
{
  if(version_in_range(version:ppviewVer, test_version:"12.0", test_version2:"12.0.6550.4999") ||
     version_in_range(version:ppviewVer, test_version:"14.0", test_version2:"14.0.5136.5002")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
