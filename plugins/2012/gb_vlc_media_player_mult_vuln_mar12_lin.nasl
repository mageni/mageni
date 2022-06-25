###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_mult_vuln_mar12_lin.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# VLC Media Player Multiple Vulnerabilities - Mar 12 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802723");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-1775", "CVE-2012-1776");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-21 11:52:20 +0530 (Wed, 21 Mar 2012)");
  script_name("VLC Media Player Multiple Vulnerabilities - Mar 12 (Linux)");
  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1201.html");
  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1202.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_mandatory_keys("VLCPlayer/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service or
  possibly execute arbitrary code via crafted streams.");
  script_tag(name:"affected", value:"VLC media player version prior to 2.0.1 on Linux");
  script_tag(name:"insight", value:"The flaws are due to multiple buffer overflow errors in the
  application, which allows remote attackers to execute arbitrary code via
  crafted MMS:// stream and Real RTSP streams.");
  script_tag(name:"solution", value:"Upgrade to VLC media player version 2.0.1 or later.");
  script_tag(name:"summary", value:"This host is installed with VLC Media Player and is prone to
  multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.videolan.org/vlc/");
  exit(0);
}


include("version_func.inc");

vlcVer = get_kb_item("VLCPlayer/Lin/Ver");
if(!vlcVer){
  exit(0);
}

if(version_is_less(version:vlcVer, test_version:"2.0.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
