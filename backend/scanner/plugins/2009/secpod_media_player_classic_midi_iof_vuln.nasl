###############################################################################
# OpenVAS Vulnerability Test
#
# Gabset Media Player Classic Integer Overflow Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900948");
  script_version("2019-05-10T14:24:23+0000");
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3201");
  script_bugtraq_id(36333);
  script_name("Gabset Media Player Classic Integer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/385461.php");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_media_player_classic_detect.nasl");
  script_mandatory_keys("MediaPlayerClassic/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows the attacker to execute arbitrary codes and may
crash the player.");
  script_tag(name:"affected", value:"Gabset Media Player Classic 6.4.9 and prior on Windows.");
  script_tag(name:"insight", value:"An integer overflow occurs when processing specially crafted MIDI (.mid) files
 containing a malformed header.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Gabset Media Player Classic and is
prone to Integer Overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

mpcVer = get_kb_item("MediaPlayerClassic/Ver");
if(!mpcVer) {
  exit(0);
}

if(version_is_less_equal(version:mpcVer, test_version:"6.4.9")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
