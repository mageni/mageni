###############################################################################
# OpenVAS Vulnerability Test
#
# Apple iTunes '.m3u' Playlist Code Execution Vulnerabilities (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802862");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2012-0677");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2012-06-12 16:25:52 +0530 (Tue, 12 Jun 2012)");
  script_name("Apple iTunes '.m3u' Playlist Code Execution Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5318");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49489");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027142");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Jun/msg00000.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"Apple iTunes version prior to 10.6.3 on Windows");
  script_tag(name:"insight", value:"Apple iTunes fails to handle '.m3u' playlist, allowing to cause a heap
  overflow and execute arbitrary code on the target system.");
  script_tag(name:"solution", value:"Upgrade to Apple Apple iTunes version 10.6.3 or later.");
  script_tag(name:"summary", value:"This host is installed with Apple iTunes and is prone to multiple
  code execution vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.apple.com/itunes/download/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

## Apple iTunes version < 10.6.3 (10.6.3.25)
if( version_is_less( version:vers, test_version:"10.6.3.25" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.6.3.25", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );