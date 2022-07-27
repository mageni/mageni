###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Untrusted search path vulnerability (Windows)
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801465");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_cve_id("CVE-2010-3976");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Player Untrusted search path vulnerability (windows)");
  script_xref(name:"URL", value:"http://www.derkeiler.com/Mailing-Lists/securityfocus/bugtraq/2010-09/msg00070.html");
  script_xref(name:"URL", value:"http://core.yehg.net/lab/pr0js/advisories/dll_hijacking/[flash_player]_10.1.x_insecure_dll_hijacking_(dwmapi.dll)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to trigger user to
save a malicious dll file in users Desktop.");
  script_tag(name:"affected", value:"Adobe Flash Player version 10.1.0 through 10.1.82.76");
  script_tag(name:"insight", value:"The application passes an insufficiently qualified path in
loading its external libraries 'dwmapi.dll'.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 10.1.102.64 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to
untrusted search path vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.adobe.com/support/flashplayer/downloads.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_in_range( version:vers, test_version:"10.1.0", test_version2:"10.1.82.76" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.1.102.64", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );