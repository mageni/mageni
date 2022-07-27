###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Remote Code Execution Vulnerability (2639185)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.903017");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-0177");
  script_bugtraq_id(52867);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-04-11 09:32:29 +0530 (Wed, 11 Apr 2012)");
  script_name("Microsoft Office Remote Code Execution Vulnerability (2639185)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48723/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74556");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026910");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS12-028");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"Microsoft Works 6 to 9 File Converter

  Microsoft Office 2007 Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaw is due to an error in the Works Converter and can be
  exploited to cause a heap-based buffer overflow via a specially crafted
  Works '.wps' file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-028.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
if(!path){
  exit(0);
}

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2007
if(officeVer && officeVer =~ "^12\.")
{
  cnvVer = fetch_file_version(sysPath:path, file_name:"Microsoft Shared\TextConv\Works632.cnv");
  if(cnvVer)
  {
    if(version_is_less(version:cnvVer, test_version:"9.11.0707.0"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

## Microsoft Works 6 to 9 File Converter
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  wfcName = registry_get_sz(key:key + item, item:"DisplayName");

  if(!wfcName){
    continue;
  }

  if("Microsoft Works 6-9 Converter" >< wfcName)
  {
    dllVer = fetch_file_version(sysPath:path,
                          file_name:"Microsoft Shared\TextConv\Wkcvqr01.dll");
    if(!dllVer){
      exit(0);
    }

    if(version_is_less(version:dllVer, test_version:"9.8.1117.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
