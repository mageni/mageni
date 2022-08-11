###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft InfoPath Memory Corruption Vulnerability (3141806)
#
# Authors:
# Kashianth T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807603");
  script_version("2019-05-24T11:20:30+0000");
  script_cve_id("CVE-2015-2503");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2016-03-09 14:51:16 +0530 (Wed, 09 Mar 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft InfoPath Memory Corruption Vulnerability (3141806)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-029.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to Office software fails
  to properly handle objects in memory");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft InfoPath 2007 Service Pack 3

  Microsoft InfoPath 2010 Service Pack 2

  Microsoft InfoPath 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114426");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114414");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114833");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-029");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms16-029");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## InfoPath 2010
if(registry_key_exists(key:"SOFTWARE\Microsoft\Office\14.0\InfoPath\InstallRoot")){
  new_key = "SOFTWARE\Microsoft\Office\14.0\InfoPath\InstallRoot";
}
## InfoPath 2007
else if (registry_key_exists(key:"SOFTWARE\Microsoft\Office\12.0\InfoPath\InstallRoot")){
  new_key = "SOFTWARE\Microsoft\Office\12.0\InfoPath\InstallRoot";
}

## InfoPath 2013
else if (registry_key_exists(key:"SOFTWARE\Microsoft\Office\15.0\InfoPath\InstallRoot")){
  new_key = "SOFTWARE\Microsoft\Office\15.0\InfoPath\InstallRoot";
}

# None of these products installed
else {
  exit(0);
}

infoPath = registry_get_sz(key:new_key, item:"Path");
if(infoPath)
{
  exeVer = fetch_file_version(sysPath:infoPath, file_name:"ipdesign.dll");
  if(exeVer =~ "^(12|14|15)\..*")
  {
    if(exeVer =~ "^12"){
      Vulnerable_range  =  "12 - 12.0.6744.4999";
    }
    else if(exeVer =~ "^14"){
      Vulnerable_range  =  "14 - 14.0.7167.4999";
    }
    else if(exeVer =~ "^15"){
      Vulnerable_range  =  "15 - 15.0.4805.0999";
    }

    if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6744.4999") ||
       version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7167.4999") ||
       version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4805.0999"))
    {
      report = 'File checked:  ipdesign.dll' + '\n' +
               'File version:     ' + exeVer  + '\n' +
               'Vulnerable range: ' + Vulnerable_range + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
