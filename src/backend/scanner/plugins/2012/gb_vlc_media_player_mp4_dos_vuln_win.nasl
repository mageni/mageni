###############################################################################
# OpenVAS Vulnerability Test
#
# VLC Media Player 'MP4' Denial of Service Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802920");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2012-2396");
  script_bugtraq_id(53535, 53169);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2012-07-25 13:06:00 +0530 (Wed, 25 Jul 2012)");
  script_name("VLC Media Player 'MP4' Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49159");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75038");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18757");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/111991/VLC-2.0.1-Division-By-Zero.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to crash the affected
application, denying service to legitimate users.");
  script_tag(name:"affected", value:"VLC media player version 2.0.1 on Windows");
  script_tag(name:"insight", value:"A division by zero error exists when handling MP4 files, which
can be exploited to cause a crash.");
  script_tag(name:"solution", value:"Update to version 2.0.2 or later.");
  script_tag(name:"summary", value:"This host is installed with VLC Media Player and is prone to
denial of service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.videolan.org/vlc");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_equal( version:vers, test_version:"2.0.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.2", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );