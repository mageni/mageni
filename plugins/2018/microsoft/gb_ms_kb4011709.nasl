###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Web Apps 2010 Service Pack 2 Multiple Vulnerabilities (KB4011709)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812990");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2018-0919", "CVE-2018-0922");
  script_bugtraq_id(103311, 103314);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-14 12:06:56 +0530 (Wed, 14 Mar 2018)");
  script_name("Microsoft Office Web Apps 2010 Service Pack 2 Multiple Vulnerabilities (KB4011709)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011709");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - An error in Microsoft Office software when the Office software fails to
    properly handle objects in memory.

  - An error when Microsoft Office software reads out of bound memory due to
    an uninitialized variable, which could disclose the contents of memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to run arbitrary code in the context
  of the current user and to view out of bound memory.");

  script_tag(name:"affected", value:"Microsoft Office Web Apps 2010 Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011709");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_web_apps_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Web/Apps/Ver");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:'cpe:/a:microsoft:office_web_apps', exit_no_version:TRUE) ) exit( 0 );

webappVer = infos['version'];
if(!webappVer){
  exit(0);
}

path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

if(webappVer =~ "^(14\.)")
{
  dllVer = fetch_file_version(sysPath:path,
           file_name:"\14.0\WebServices\ConversionService\Bin\Converter\sword.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7195.4999"))
    {
      report = report_fixed_ver(file_checked:path + "\14.0\WebServices\ConversionService\Bin\Converter\sword.dll",
                          file_version:dllVer, vulnerable_range:"14.0 - 14.0.7195.4999");
      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);
