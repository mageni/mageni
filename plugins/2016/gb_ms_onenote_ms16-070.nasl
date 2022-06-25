###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft OneNote Remote Code Execution Vulnerability (3114862)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:microsoft:onenote";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808229");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-06-16 11:22:43 +0530 (Thu, 16 Jun 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft OneNote Remote Code Execution Vulnerability (3114862)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-070.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist when a user opens a specially
  crafted Office file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft OneNote 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114862");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-070");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_onenote_detect.nasl");
  script_mandatory_keys("MS/Office/OneNote/Ver");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms16-070");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );

exeVer = infos['version'];

notePath = infos['location'];
if( ! notePath ) notePath =  "Unable to fetch full installation path";

if(exeVer && exeVer =~ "^16.*") {
  if(version_in_range(version:exeVer, test_version:"16.0", test_version2:"16.0.4366.999")) {
     report = 'File checked:     ' + notePath + 'onenote.exe'  + '\n' +
              'File version:     ' + exeVer  + '\n' +
              'Vulnerable range:   16.0 - 16.0.4366.999' + '\n' ;
     security_message(data:report);
     exit(0);
  }
}

exit( 99 );