###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Live Meeting 2007 Console Multiple Vulnerabilities (KB4025868)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:microsoft:office_live_meeting";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811690");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-8676", "CVE-2017-8695", "CVE-2017-8696");
  script_bugtraq_id(100755, 100773, 100780);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-13 16:16:50 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Live Meeting 2007 Console Multiple Vulnerabilities (KB4025868)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4025868");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - The way that the Windows Graphics Device Interface (GDI) handles objects in
    memory, allowing an attacker to retrieve information from a targeted system.

  - When Windows Uniscribe improperly discloses the contents of its memory.

  - The way Windows Uniscribe handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to retrieve information from a targeted system. By itself, the information
  disclosure does not allow arbitrary code execution. However, it could allow
  arbitrary code to be run if the attacker uses it in combination with another
  vulnerability.");

  script_tag(name:"affected", value:"Microsoft Live Meeting 2007 Console");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025868");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_live_meeting_detect.nasl");
  script_mandatory_keys("MS/OfficeLiveMeeting/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

appPath = get_app_location(cpe:CPE);
if(!appPath ||  "Couldn find the install location" >< appPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:appPath, file_name:"Ogl.dll");
if(!dllVer){
  exit(0);
}

if(version_is_less(version:dllVer, test_version:"12.0.6776.5000"))
{
  report = 'File checked:     ' +  appPath + "Ogl.dll"+ '\n' +
           'File version:     ' +  dllVer  + '\n' +
           'Vulnerable range: Less than 12.0.6776.5000\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
