###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_realplayer_asm_ruleboook_bof_lin.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# RealNetworks RealPlayer ASM RuleBook BOF Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902110");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4247");
  script_bugtraq_id(37880);
  script_name("RealNetworks RealPlayer ASM RuleBook BOF Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38218");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55794");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0178");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/01192010_player/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_realplayer_detect_lin.nasl");
  script_mandatory_keys("RealPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes within
  the context of the application and can cause heap overflow or cause remote
  code execution.");
  script_tag(name:"affected", value:"RealPlayer versions 10.x and 11.0.0 on Linux platforms.");
  script_tag(name:"insight", value:"The buffer overflow error occurs when processing a malformed 'ASM RuleBook'.");
  script_tag(name:"solution", value:"Upgrade to RealPlayer version 11.0.5 or later.");
  script_tag(name:"summary", value:"This host is installed with RealPlayer which is prone to Buffer
  Overflow vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.real.com/player");
  exit(0);
}


include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Linux/Ver");
if(isnull(rpVer)){
  exit(0);
}

if((rpVer =~ "^10\.*") || (rpVer =~ "^11\.0\.1.*")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
