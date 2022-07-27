###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vlc_media_player_bof_vuln_lin_mar09.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# VLC Media Player Stack Overflow Vulnerability (Lin-Mar09)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900531");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1045");
  script_bugtraq_id(34126);
  script_name("VLC Media Player Stack Overflow Vulnerability (Lin-Mar09)");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8213");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49249");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=262708");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/03/17/4");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_mandatory_keys("VLCPlayer/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows the attacker to execute arbitrary codes
  with escalated privileges and cause overflow in stack.");
  script_tag(name:"affected", value:"VLC media player 0.9.8a and prior on Linux.");
  script_tag(name:"insight", value:"This flaw is due to improper boundary checking in status.xml in the web
  interface by an overly long request.");
  script_tag(name:"solution", value:"Upgrade to VLC media player version 1.0 or later.");
  script_tag(name:"summary", value:"This host is installed with VLC Media Player and is prone to
  Stack Overflow Vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.videolan.org/vlc");
  exit(0);
}


include("version_func.inc");

vlcVer = get_kb_item("VLCPlayer/Lin/Ver");
if(!vlcVer){
  exit(0);
}

if(version_is_less_equal(version:vlcVer, test_version:"0.9.8a")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
