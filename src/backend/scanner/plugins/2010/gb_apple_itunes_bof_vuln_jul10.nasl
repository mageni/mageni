###############################################################################
# OpenVAS Vulnerability Test
#
# Apple iTunes 'itpc:' URI Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801409");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_bugtraq_id(41789);
  script_cve_id("CVE-2010-1777");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple iTunes 'itpc:' URI Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://isc.sans.edu/diary.html?storyid=9202");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jul/1024220.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow the attacker to execute arbitrary code in
  the context of an application. Failed exploit attempts will result in a
  denial-of-service condition.");
  script_tag(name:"affected", value:"Apple iTunes version prior to 9.2.1");
  script_tag(name:"insight", value:"The flaw exists in the handling of 'itpc:' URL, when loaded by the user
  will trigger a buffer overflow and execute arbitrary code on the target
  system.");
  script_tag(name:"solution", value:"Upgrade to Apple iTunes version 9.2.1 or later.");
  script_tag(name:"summary", value:"This host has iTunes installed and is prone to a buffer overflow
  vulnerability.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.apple.com/itunes/download/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"9.2.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.2.1", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
