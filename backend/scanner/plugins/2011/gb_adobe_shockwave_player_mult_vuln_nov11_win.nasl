###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_mult_vuln_nov11_win.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# Adobe Shockwave Player Multiple Vulnerabilities (Windows) - Nov 2011
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802508");
  script_version("$Revision: 11987 $");
  script_cve_id("CVE-2011-2446", "CVE-2011-2447", "CVE-2011-2448", "CVE-2011-2449");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-10 12:17:59 +0530 (Thu, 10 Nov 2011)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities (Windows) - Nov 2011");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46667/");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-27.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code or
  to cause a denial of service.");
  script_tag(name:"affected", value:"Adobe Shockwave Player Versions prior to 11.6.3.633 on Windows.");
  script_tag(name:"insight", value:"Multiple flaws are due to an error in,

  - DIRAPI.dll and TextXtra.x32 when parsing Director file headers.

  - DIRAPI.dll when parsing rcsl chunks within Director files.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version 11.6.3.633 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Shockwave Player and is prone
  to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://get.adobe.com/shockwave/otherversions/");
  exit(0);
}


include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less(version:shockVer, test_version:"11.6.3.633")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
