###############################################################################
# OpenVAS Vulnerability Test
#
# VLC Media Player SMB 'Win32AddConnection()' BOF Vulnerability - July09 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800663");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2484");
  script_bugtraq_id(35500);
  script_name("VLC Media Player SMB 'Win32AddConnection()' BOF Vulnerability - July09 (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35558");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9029");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1714");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code, and can
  cause application crash.");
  script_tag(name:"affected", value:"VLC Media Player version 0.9.9 and prior on Windows.");
  script_tag(name:"insight", value:"Stack-based Buffer overflow error in the 'Win32AddConnection' function in
  modules/access/smb.c while processing a specially crafted long 'smb://' URI
  within a playlist.");
  script_tag(name:"summary", value:"This host is installed with VLC Media Player and is prone to
  Stack-Based Buffer Overflow Vulnerability.");
  script_tag(name:"solution", value:"Apply the available patch  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://git.videolan.org/?p=vlc.git;a=commit;h=e60a9038b13b5eb805a76755efc5c6d5e080180f");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version:vers, test_version:"0.9.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );