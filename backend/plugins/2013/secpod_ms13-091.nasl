###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Remote Code Execution Vulnerabilities (2885093)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903414");
  script_version("2019-05-21T06:50:08+0000");
  script_cve_id("CVE-2013-0082", "CVE-2013-1324", "CVE-2013-1325");
  script_bugtraq_id(63559, 63569, 63570);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-21 06:50:08 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2013-11-13 15:08:45 +0530 (Wed, 13 Nov 2013)");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2885093)");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-091.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Flaws are due to an error when parsing WordPerfect documents files (.wpd).");

  script_tag(name:"affected", value:"Microsoft Office 2013

  Microsoft Office 2003 Service Pack 3 and prior

  Microsoft Office 2007 Service Pack 3 and prior

  Microsoft Office 2010 Service Pack 1  and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to corrupt memory, cause
  a buffer overflow and execution the arbitrary code.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55539");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2760494");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2760781");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2768005");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-091");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## MS Office 2003
offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!path){
  exit(0);
}

## Office 2003 text converters
if(offVer =~ "^11\.")
{
  filePath = path + "\Microsoft Shared\TextConv";
  fileVer = fetch_file_version(sysPath:filePath, file_name:"msconv97.dll");
  if(fileVer)
  {
    if(version_in_range(version:fileVer, test_version:"2003", test_version2:"2003.1100.8326"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

## Microsoft Office 2013 (file formats)
if(offVer =~ "^1[245]\.")
{
  filePath = path + "\Microsoft Shared\TextConv";
  ##
  fileVer = fetch_file_version(sysPath:filePath, file_name:"Wpft532.cnv");
  if(fileVer)
  {
    ## Microsoft Office 2007 File Formats
    ## Microsoft Office 2013 (file formats)
    ## Microsoft Office 2010 (file format converters)
    if(version_in_range(version:fileVer, test_version:"2012", test_version2:"2012.1500.4525.0999")||
       version_in_range(version:fileVer, test_version:"2010", test_version2:"2010.1400.7011.0999") ||
       version_in_range(version:fileVer, test_version:"2006", test_version2:"2006.1200.6676.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
