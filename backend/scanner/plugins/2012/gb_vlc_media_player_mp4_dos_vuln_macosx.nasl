###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_mp4_dos_vuln_macosx.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# VLC Media Player 'MP4' Denial of Service Vulnerability (Mac OS X)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802921");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2012-2396");
  script_bugtraq_id(53535, 53169);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-25 13:33:36 +0530 (Wed, 25 Jul 2012)");
  script_name("VLC Media Player 'MP4' Denial of Service Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49159");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75038");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18757");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/111991/VLC-2.0.1-Division-By-Zero.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to crash the affected
application, denying service to legitimate users.");
  script_tag(name:"affected", value:"VLC media player version 2.0.1 on Mac OS X.");
  script_tag(name:"insight", value:"A division by zero error exists when handling MP4 files, which
can be exploited to cause a crash.");
  script_tag(name:"solution", value:"Update to version 1.7.2 or later.");
  script_tag(name:"summary", value:"This host is installed with VLC Media Player and is prone to
denial of service vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.videolan.org/vlc");
  exit(0);
}


include("version_func.inc");

vlcVer = get_kb_item("VLC/Media/Player/MacOSX/Version");
if(!vlcVer){
  exit(0);
}

if(version_is_equal(version:vlcVer, test_version:"2.0.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
