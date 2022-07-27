###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms15-059.nasl 0049763 2015-06-10 17:04:18Z June$
#
# Microsoft Office Suite Remote Code Execution Vulnerabilities (3064949)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805069");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2015-1759", "CVE-2015-1760", "CVE-2015-1770");
  script_bugtraq_id(75014, 75015, 75016);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-06-10 09:23:47 +0530 (Wed, 10 Jun 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Suite Remote Code Execution Vulnerabilities (3064949)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-059.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists as user supplied input is
  not properly validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to corrupt memory and potentially
  execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Office 2010 Service Pack 2 and prior
  Microsoft Office 2013 Service Pack 1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3064949");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-059");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_office_detection_900025.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## MS Office
offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!path){
  exit(0);
}

## Microsoft Office 2010
## Microsoft Office 2013
if(offVer =~ "^(14|15)\..*")
{
  filePath = path + "\Microsoft Shared\TextConv";

  fileVer = fetch_file_version(sysPath:filePath, file_name:"Wpft532.cnv");
  if(fileVer)
  {
    ## Microsoft Office 2013
    ## Microsoft Office 2010
    if(version_in_range(version:fileVer, test_version:"2012", test_version2:"2012.1500.4727.0999")||
       version_in_range(version:fileVer, test_version:"2010", test_version2:"2010.1400.4730.1009") ||
       version_in_range(version:fileVer, test_version:"2006", test_version2:"2006.1200.6722.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}


## https://support.microsoft.com/en-us/kb/3039782
path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                           item:"ProgramFilesDir");
if(path)
{
  sysVer = fetch_file_version(sysPath:path + "\Microsoft Office\Office15", file_name:"osf.dll");
  if(sysVer)
  {
    if(version_in_range(version:sysVer, test_version:"15.0", test_version2:"15.0.4725.0999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
