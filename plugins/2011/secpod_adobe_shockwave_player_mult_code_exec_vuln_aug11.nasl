###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_shockwave_player_mult_code_exec_vuln_aug11.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Adobe Shockwave Player Multiple Remote Code Execution Vulnerabilities - Aug 2011
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902617");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2010-4308", "CVE-2010-4309", "CVE-2011-2419", "CVE-2011-2420",
                "CVE-2011-2421", "CVE-2011-2422", "CVE-2011-2423");
  script_bugtraq_id(49102);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Adobe Shockwave Player Multiple Remote Code Execution Vulnerabilities - Aug 2011");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45584");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-19.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause Denial of Service or
  execute arbitrary code by tricking a user into visiting a specially crafted
  web page.");
  script_tag(name:"affected", value:"Adobe Shockwave Player Versions prior to 11.6.1.629 on Windows.");
  script_tag(name:"insight", value:"Multiple flaws are caused by memory corruptions errors in the IML32.dll,
  Dirapi.dll, Textra.x32 and msvcr90.dll component when processing malformed
  '.dir' media file.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version 11.6.1.629 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Shockwave Player and is prone
  to multiple remote code execution vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://get.adobe.com/shockwave/otherversions/");
  exit(0);
}


include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less(version:shockVer, test_version:"11.6.1.629")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
