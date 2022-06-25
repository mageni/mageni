###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_bof_vuln_jan10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Shockwave Player 3D Model Buffer Overflow Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.800443");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4003", "CVE-2009-4002");
  script_bugtraq_id(37872, 37870);
  script_name("Adobe Shockwave Player 3D Model Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-61/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0171");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jan/1023481.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-03.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/509062/100/0/threaded");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful attack could allow attackers to execute arbitrary code and compromise
  a vulnerable system.");
  script_tag(name:"affected", value:"Adobe Shockwave Player prior to 11.5.6.606 on Windows.");
  script_tag(name:"insight", value:"These flaws are caused by buffer and integer overflow errors when processing
  Shockwave files or 3D models, which could be exploited to execute arbitrary
  code by tricking a user into visiting a specially crafted web page.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player 11.5.6.606 or later.");
  script_tag(name:"summary", value:"This host has Adobe Shockwave Player installed and is prone to
  Buffer Overflow vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://get.adobe.com/shockwave/otherversions/");
  exit(0);
}


include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less(version:shockVer, test_version:"11.5.6.606")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
