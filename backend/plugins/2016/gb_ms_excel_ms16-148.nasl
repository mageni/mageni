###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Excel Multiple Vulnerabilities (3204068)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809749");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-7262", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266",
                "CVE-2016-7267");
  script_bugtraq_id(94769, 94721, 94662, 94664);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-12-14 08:28:11 +0530 (Wed, 14 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Excel Multiple Vulnerabilities (3204068)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-148.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as

  - Microsoft Office improperly handles input.

  - Microsoft Office software reads out of bound memory.

  - Microsoft Office software improperly handles the parsing of file formats.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and gain
  access to potentially sensitive information.");

  script_tag(name:"affected", value:"Microsoft Excel 2007 Service Pack 3,
  Microsoft Excel 2010 Service Pack 2,
  Microsoft Excel 2013 Service Pack 1,
  Microsoft Excel 2016 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3128008");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3128016");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3128037");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3128019");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms16-148");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(!excelVer){
  exit(0);
}

excelPath = get_kb_item("SMB/Office/Excel/Install/Path");
if(!excelPath){
   excelPath = "Unable to fetch the install path";
}

if(excelVer =~ "^(12|14|15|16)\..*")
{
  if(excelVer =~ "^12"){
    Vulnerable_range  =  "12 - 12.0.6762.4999";
  }
  else if(excelVer =~ "^14"){
    Vulnerable_range  =  "14 - 14.0.7177.4999";
  }
  else if(excelVer =~ "^15"){
    Vulnerable_range  =  "15 - 15.0.4885.0999";
  }
  else if(excelVer =~ "^16"){
    Vulnerable_range  =  "16 - 16.0.4471.0999";
  }

  if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6762.4999")||
     version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.7177.4999")||
     version_in_range(version:excelVer, test_version:"15.0", test_version2:"15.0.4885.0999")||
     version_in_range(version:excelVer, test_version:"16.0", test_version2:"16.0.4471.0999"))
  {
    report = 'File checked:     ' + excelPath + "Excel.exe" + '\n' +
             'File version:     ' + excelVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
