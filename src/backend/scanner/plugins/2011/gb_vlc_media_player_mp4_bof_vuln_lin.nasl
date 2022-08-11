###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_mp4_bof_vuln_lin.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# VLC Media Player 'MP4_ReadBox_skcr()' Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801783");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_cve_id("CVE-2011-1684");
  script_bugtraq_id(47293);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("VLC Media Player 'MP4_ReadBox_skcr()' Buffer Overflow Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44022");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66664");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0916");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_mandatory_keys("VLCPlayer/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a malicious file or visiting a specially crafted
  web page.");
  script_tag(name:"affected", value:"VLC media player version prior to 1.1.9 on Linux");
  script_tag(name:"insight", value:"The flaw is caused by a heap corruption error in the 'MP4_ReadBox_skcr()'
  [modules/demux/mp4/libmp4.c] function when processing malformed MP4
  (MPEG-4 Part 14) data.");
  script_tag(name:"solution", value:"Upgrade to the VLC media player version 1.1.9 or later.");
  script_tag(name:"summary", value:"The host is installed with VLC Media Player and is prone buffer
  overflow vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://download.videolan.org/pub/videolan/vlc/");
  exit(0);
}


include("version_func.inc");

vlcVer = get_kb_item("VLCPlayer/Lin/Ver");
if(!vlcVer){
  exit(0);
}

if(version_is_less(version:vlcVer, test_version:"1.1.9")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
