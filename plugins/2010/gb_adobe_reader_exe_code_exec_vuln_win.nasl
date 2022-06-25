###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader PDF Handling Code Execution Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801303");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_cve_id("CVE-2009-1492");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Reader PDF Handling Code Execution Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://lists.immunitysec.com/pipermail/dailydave/2010-April/006074.html");
  script_xref(name:"URL", value:"http://lists.immunitysec.com/pipermail/dailydave/2010-April/006072.html");
  script_xref(name:"URL", value:"https://forum.immunityinc.com/board/thread/1199/exploiting-pdf-files-without-vulnerabili/?page=1#post-1199");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");

  script_tag(name:"affected", value:"Adobe Reader version 8.x and 9.x on Windows.");

  script_tag(name:"insight", value:"The flaw is due to error in handling  'PDF' files, which allows to execute
  'EXE' files that are embedded in a PDF document.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.3.2 or later.");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to arbitrary
  code execution vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code via
  a crafted document.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"9.3.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.3.2", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );