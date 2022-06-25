###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Word Security Bypass Vulnerability (3124585)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806191");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0012");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-01-13 12:11:00 +0530 (Wed, 13 Jan 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Word Security Bypass Vulnerability (3124585)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-004");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Office software fails to use the Address
  Space Layout Randomization (ASLR) security feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass the Address Space Layout Randomization (ASLR) security
  feature and perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"Microsoft Word 2007 Service Pack 3 and prior,
  Microsoft Word 2010 Service Pack 2 and prior,
  Microsoft Word 2013 Service Pack 1 and prior,
  Microsoft Word 2016 Service Pack 1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114557");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114549");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114526");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-004");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms16-004");
  exit(0);
}


include("version_func.inc");

##word 2007, 2010, 2013, 2016
exeVer = get_kb_item("SMB/Office/Word/Version");
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Word/Install/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

if(exeVer && exeVer =~ "^(12|14|15|16).*")
{
  if(exeVer =~ "^12"){
    Vulnerable_range  =  "12 - 12.0.6741.4999";
  }
  else if(exeVer =~ "^14"){
    Vulnerable_range  =  "14 - 14.0.7165.4999";
  }
  else if(exeVer =~ "^15"){
    Vulnerable_range  =  "15 - 15.0.4787.0999";
  }
  else if(exeVer =~ "^16"){
    Vulnerable_range  =  "16 - 16.0.4324.0999";
  }

  if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6741.4999") ||
     version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7165.4999") ||
     version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4787.0999") ||
     version_in_range(version:exeVer, test_version:"16.0", test_version2:"16.0.4324.0999"))
  {
     report = 'File checked:     ' + exePath + "winword.exe"  + '\n' +
              'File version:     ' + exeVer  + '\n' +
              'Vulnerable range: ' + Vulnerable_range + '\n' ;
     security_message(data:report);
     exit(0);
  }
}
