###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office IME (Chinese) Privilege Elevation Vulnerability (2652016)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902496");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2011-2010");
  script_bugtraq_id(50950);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-12-14 15:59:45 +0530 (Wed, 14 Dec 2011)");
  script_name("Microsoft Office IME (Chinese) Privilege Elevation Vulnerability (2652016)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47062/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2583956");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2647540");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-088");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to to execute arbitrary code
  with kernel-mode privileges.");
  script_tag(name:"affected", value:"Microsoft Pinyin IME 2010
  Microsoft Office Pinyin SimpleFast Style 2010 and
  Microsoft Office Pinyin New Experience Style 2010");
  script_tag(name:"insight", value:"The flaw is due to the Microsoft Pinyin (MSPY) Input Method Editor
  (IME) for Simplified Chinese unsafely exposing certain configuration
  options.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-088.");
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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

entries = registry_enum_keys(key:key);
if(entries == NULL){
  exit(0);
}

foreach item (entries)
{
  imeName = registry_get_sz(key:key + item, item:"DisplayName");
  if(egrep(pattern:"Microsoft Office IME .*Chinese", string:imeName))
  {
    path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                           item:"CommonFilesDir");
    if(path)
    {
      imePath = path + "\Microsoft Shared\IME14\IMETC";
      dllVer = fetch_file_version(sysPath:imePath, file_name:"Imtctip.dll");
      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6019.999"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}

## Microsoft Office Pinyin New Experience Style 2010
foreach item (entries)
{
  MSOffName = registry_get_sz(key:key + item, item:"DisplayName");
  if(egrep(pattern:"Microsoft Office IMESS .*Chinese", string:MSOffName))
  {
    path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                           item:"CommonFilesDir");
    if(path)
    {
      offPath = path + "\Microsoft Shared\IME14WR\IMESC";
      dllVer = fetch_file_version(sysPath:offPath, file_name:"Imsctip.dll");
      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.5810.999"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}
