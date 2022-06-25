###############################################################################
# OpenVAS Vulnerability Test
#
# DivX Web Player Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900537");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5259");
  script_bugtraq_id(34523);
  script_name("DivX Web Player Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/377996.php");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33196");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1044");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_divx_web_player_detect.nasl");
  script_mandatory_keys("DivX/Web/Player/Ver");
  script_tag(name:"affected", value:"DivX Web Player 1.4.2.7 and prior on Windows.");
  script_tag(name:"insight", value:"This flaw is due to the boundary checking error while processing Stream
  Format 'STRF' chunks which causes heap overflow.");
  script_tag(name:"solution", value:"Update to version 1.4.3.4.");
  script_tag(name:"summary", value:"This host is running DivX Web Player which is prone to buffer
  overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
  codes within the context of the application by tricking a user into
  opening a crafted DivX file.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

divxVer = get_kb_item("DivX/Web/Player/Ver");
if(!divxVer)
  exit(0);

if(version_is_less(version:divxVer, test_version:"1.4.3.4")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
