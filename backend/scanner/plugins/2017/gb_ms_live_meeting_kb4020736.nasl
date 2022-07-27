###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Live Meeting Add-in Remote Code Execution Vulnerability (KB4020736)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810947");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0283");
  script_bugtraq_id(98920);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-06-15 17:04:17 +0530 (Thu, 15 Jun 2017)");
  script_name("Microsoft Live Meeting Add-in Remote Code Execution Vulnerability (KB4020736)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4020736.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due the way Windows
  Uniscribe handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to execute arbitrary code on the affected system and
  take control of the affected system.");

  script_tag(name:"affected", value:"Microsoft Live Meeting 2007 Add-in");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/4020736");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4020736");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(!path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"ProgramFilesDir")){
  exit(0);
}

filepath = path + "\Microsoft Office\Live Meeting 8\Addins";

if(!liveVer = fetch_file_version(sysPath:filepath, file_name:"lmaddins.dll")){
  exit(0);
}

if(version_is_less(version:liveVer, test_version:"8.0.6362.274"))
{
  report = 'File checked:     ' +  filepath + "\lmaddins.dll\n" +
           'File version:     ' +  liveVer  + '\n' +
           'Vulnerable range: Less than 8.0.6362.274\n' ;
  security_message(data:report);
  exit(0);
}
