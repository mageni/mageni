###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_media_player_bof_vuln.nasl 11553 2018-09-22 14:22:01Z cfischer $
#
# Microsoft Windows Media Player '.mpg' Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800480");
  script_version("$Revision: 11553 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 16:22:01 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-03-02 12:36:32 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0718");
  script_name("Microsoft Windows Media Player '.mpg' Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56435");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11531");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_ms_win_media_player_detect_900173.nasl");
  script_mandatory_keys("Win/MediaPlayer/Ver");
  script_tag(name:"impact", value:"Successful exploitation will lets attacker execute arbitrary codes in
the context of the affected player.");
  script_tag(name:"affected", value:"Windows Media Player version 9.x and 11 to 11.0.5721.5145.");
  script_tag(name:"insight", value:"This flaw is due to a boundary checking error while opening a
  specially-crafted '.mpg' audio files.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is installed with Windows Media Player and is prone to
  buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

wmpVer = get_kb_item("Win/MediaPlayer/Ver");
if(!wmpVer){
  exit(0);
}

if(wmpVer =~ "^(9|11)\..*$")
{
  if(version_in_range(version:wmpVer, test_version:"9.0", test_version2:"9.0.0.4503") ||
     version_in_range(version:wmpVer, test_version:"11.0", test_version2:"11.0.5721.5145")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
