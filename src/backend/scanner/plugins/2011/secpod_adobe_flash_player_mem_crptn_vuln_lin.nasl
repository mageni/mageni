###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_flash_player_mem_crptn_vuln_lin.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Adobe Flash Player Remote Memory Corruption Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902401");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_cve_id("CVE-2011-0609");
  script_bugtraq_id(46860);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Player Remote Memory Corruption Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-06.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa11-01.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service.");
  script_tag(name:"affected", value:"Adobe Flash Player version 10.2.152.33 and prior on Linux.");
  script_tag(name:"insight", value:"The flaw is due to an error when handling the 'SWF' file, which allows
  attackers to execute arbitrary code or cause a denial of service via crafted
  flash content.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 10.2.153.1 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to
  memory corruption vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.adobe.com/downloads/");
  exit(0);
}


include("version_func.inc");

flashVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!flashVer){
  exit(0);
}

flashVer = ereg_replace(pattern:",", string:flashVer, replace: ".");

if(version_is_less_equal(version:flashVer, test_version:"10.2.152.33")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
