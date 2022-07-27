###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_shockwave_player_mult_vuln_nov10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Shockwave Player Multiple Vulnerabilities Nov-10
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.901167");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:49:11 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-2581", "CVE-2010-2582", "CVE-2010-3653", "CVE-2010-3655",
                "CVE-2010-4084", "CVE-2010-4085", "CVE-2010-4086", "CVE-2010-4087",
                "CVE-2010-4088", "CVE-2010-4089", "CVE-2010-4090");
  script_bugtraq_id(44512, 44514, 44291, 44516, 44520, 44517, 44518, 44519, 44521,
                    44515);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities Nov-10");


  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code by
  tricking a user into visiting a specially crafted web page.");
  script_tag(name:"affected", value:"Adobe Shockwave Player prior to 11.5.9.615 on Windows");
  script_tag(name:"insight", value:"The multiple flaws are caused by memory corruptions and buffer overflow errors
  in the 'DIRAPI.dll' and 'IML32.dll' modules when processing malformed Shockwave
  or Director files.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player 11.5.9.615");
  script_tag(name:"summary", value:"This host is installed with Adobe Shockwave Player and is prone
  to multiple vulnerabilities.");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2826");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-25.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://get.adobe.com/shockwave/");
  exit(0);
}


include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less(version:shockVer, test_version:"11.5.9.615")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
