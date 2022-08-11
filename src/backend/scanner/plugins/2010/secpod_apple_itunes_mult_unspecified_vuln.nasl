###############################################################################
# OpenVAS Vulnerability Test
#
# Apple iTunes Multiple Unspecified Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902201");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-06-25 16:56:31 +0200 (Fri, 25 Jun 2010)");
  script_cve_id("CVE-2010-1769", "CVE-2010-1763", "CVE-2010-1387");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Apple iTunes Multiple Unspecified Vulnerabilities");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4220");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jun/1024108.html");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2010//Jun/msg00002.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
  script_tag(name:"impact", value:"Further details about the vulnerability is not known.");
  script_tag(name:"affected", value:"Apple iTunes version prior to 9.2 (9.2.0.61)");
  script_tag(name:"insight", value:"An unspecified vulnerabilities exists in 'WebKit' within Apple iTunes.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Apple iTunes version 9.2 or later.");
  script_tag(name:"summary", value:"This host has iTunes installed, which is prone to multiple
  unspecified vulnerabilities.");
  script_xref(name:"URL", value:"http://www.apple.com/itunes/download/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

#  Apple iTunes version < 9.2 (9.2.0.61)
if( version_is_less( version:vers, test_version:"9.2.0.61" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.2.0.61", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );