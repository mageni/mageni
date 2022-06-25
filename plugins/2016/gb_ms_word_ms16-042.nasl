###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Word Remote Code Execution Vulnerability (3148775)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807317");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-0127");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-04-13 10:55:39 +0530 (Wed, 13 Apr 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Word Remote Code Execution Vulnerability (3148775)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-042");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as office software fails
  to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Word 2007 Service Pack 3 and prior,
  Microsoft Word 2010 Service Pack 2 and prior,
  Microsoft Word 2013 Service Pack 1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-in/kb/3114937");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-in/kb/3114983");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-in/kb/3114993");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-042");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms16-042");
  exit(0);
}


include("version_func.inc");

exeVer = get_kb_item("SMB/Office/Word/Version");
if(exeVer && exeVer =~ "^(12|14|15).*")
{
  if(exeVer =~ "^12"){
    Vulnerable_range  =  "12 - 12.0.6747.4999";
  }
  else if(exeVer =~ "^14"){
    Vulnerable_range  =  "14 - 14.0.7168.4999";
  }
  else if(exeVer =~ "^15"){
    Vulnerable_range  =  "15 - 15.0.4815.0999";
  }

  if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6747.4999") ||
     version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7168.4999") ||
     version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4815.0999"))
  {
     report = 'File checked:     winword.exe'  + '\n' +
              'File version:     ' + exeVer  + '\n' +
              'Vulnerable range: ' + Vulnerable_range + '\n' ;
     security_message(data:report);
     exit(0);
  }
}
