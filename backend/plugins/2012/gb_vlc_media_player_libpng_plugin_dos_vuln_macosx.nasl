###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_libpng_plugin_dos_vuln_macosx.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# VLC Media Player 'libpng_plugin' Denial of Service Vulnerability (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802489");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-5470");
  script_bugtraq_id(55850);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-11-02 14:31:32 +0530 (Fri, 02 Nov 2012)");
  script_name("VLC Media Player 'libpng_plugin' Denial of Service Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/21889/");
  script_xref(name:"URL", value:"http://www.videolan.org/vlc/releases/2.0.4.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/10/24/3");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to crash the affected
  application and denying service to legitimate users.");
  script_tag(name:"affected", value:"VLC media player version 2.0.3 and prior on Mac OS X");
  script_tag(name:"insight", value:"The flaw is due to an error in 'libpng_plugin' when handling a crafted PNG
  file. Which can be exploited to cause a crash.");
  script_tag(name:"solution", value:"Upgrade to VLC media player 2.0.4 or later.");
  script_tag(name:"summary", value:"This host is installed with VLC Media Player and is prone to
  denial of service vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

vlcVer = get_kb_item("VLC/Media/Player/MacOSX/Version");
if(!vlcVer){
  exit(0);
}

if(version_is_less(version:vlcVer, test_version:"2.0.4")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
