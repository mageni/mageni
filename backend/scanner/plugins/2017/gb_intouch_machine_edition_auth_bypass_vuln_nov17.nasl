###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intouch_machine_edition_auth_bypass_vuln_nov17.nasl 12467 2018-11-21 14:04:59Z cfischer $
#
# InTouch Machine Edition Authentication Bypass Vulnerability Nov17 (Windows)
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

CPE = "cpe:/a:schneider_electric:intouch_machine_edition";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812218");
  script_version("$Revision: 12467 $");
  script_cve_id("CVE-2017-13997");
  script_bugtraq_id(100952);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 15:04:59 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-11-20 14:22:07 +0530 (Mon, 20 Nov 2017)");
  script_name("InTouch Machine Edition Authentication Bypass Vulnerability Nov17 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_intouch_machine_edition_detect_win.nasl");
  script_mandatory_keys("InTouch/MachineEdition/Win/Ver");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-264-01");
  script_xref(name:"URL", value:"http://www.indusoft.com");

  script_tag(name:"summary", value:"This host is installed with InTouch
  Machine Edition and is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to missing authentication
  for a critical function.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to bypass the authentication mechanism and can trigger the execution
  of an arbitrary command. The command is executed under high privileges and
  could lead to a complete compromise of the server.");

  script_tag(name:"affected", value:"Schneider Electric InTouch Machine Edition
  v8.0 SP2 or prior on Windows.");

  script_tag(name:"solution", value:"Upgrade to InTouch Machine Edition
  v8.0 SP2 Patch 1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE)) exit(0);
itmVer = infos['version'];
path = infos['location'];

# nb: Version 8.0 Service Pack 2 == 80.2.0
if(version_is_less_equal(version:itmVer, test_version:"80.2.0")){
  report = report_fixed_ver( installed_version:itmVer, fixed_version:"80.2.1", install_path:path );
  security_message( data:report);
  exit(0);
}
