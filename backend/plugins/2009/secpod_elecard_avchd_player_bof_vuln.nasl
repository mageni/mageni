###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_elecard_avchd_player_bof_vuln.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# Elecard AVC HD  Player Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
# #
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
  script_oid("1.3.6.1.4.1.25623.1.0.900627");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1356");
  script_bugtraq_id(34560);
  script_name("Elecard AVC HD  Player Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8452");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/378145.php");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_elecard_avchd_player_detect.nasl");
  script_mandatory_keys("Elecard/AVC/HD/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allows attacker to execute arbitrary code
  in the context of the affected application.");
  script_tag(name:"affected", value:"Elecard AVC HD Player 5.5.90213 and prior on Windows.");
  script_tag(name:"insight", value:"Application fails to perform adequate boundary checks on user-supplied input
  which results in a buffer overflow while processing playlist(.xpl) containing
  long MP3 filenames.");
  script_tag(name:"solution", value:"Upgrade to Elecard AVC HD Player version 5.6.90515 or later");
  script_tag(name:"summary", value:"This host is installed Elecard AVC HD Player and is prone to Buffer
  Overflow Vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.elecard.com/download/index.php");
  exit(0);
}


include("version_func.inc");

avcPlayer = get_kb_item("Elecard/AVC/HD/Ver");
if(!avcPlayer){
  exit(0);
}

if(version_is_less_equal(version:avcPlayer, test_version:"5.5.90213")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
