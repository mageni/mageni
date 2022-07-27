###############################################################################
# OpenVAS Vulnerability Test
#
# VLC Media Player Meta-Information Denial of Service Vulnerability (Windows)
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

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801429");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)");
  script_cve_id("CVE-2010-2937");
  script_bugtraq_id(42386);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("VLC Media Player Meta-Information Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/");
  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1004.html");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to crash the affected
  application, denying service to legitimate users.");
  script_tag(name:"affected", value:"VLC media player version prior to 1.1.3 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to an input validation error when trying to extract
  meta-informations about input media through 'ID3v2' tags.");
  script_tag(name:"solution", value:"Upgrade to the VLC media player version 1.1.3 or later.");
  script_tag(name:"summary", value:"The host is installed with VLC Media Player and is prone to Denial
  of Service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.videolan.org/vlc/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"1.1.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.3", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );