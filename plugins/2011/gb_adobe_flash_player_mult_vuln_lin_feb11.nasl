###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln_lin_feb11.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Adobe Flash Player Multiple Vulnerabilities February-2011 (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801848");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_cve_id("CVE-2011-0558", "CVE-2011-0559", "CVE-2011-0560",
                "CVE-2011-0561", "CVE-2011-0571", "CVE-2011-0572",
                "CVE-2011-0573", "CVE-2011-0574", "CVE-2011-0575",
                "CVE-2011-0577", "CVE-2011-0578", "CVE-2011-0607",
                "CVE-2011-0608");
  script_bugtraq_id(46186, 46188, 46189, 46190, 46191, 46192, 46193,
                    46194, 46195, 46196, 46197, 46282, 46283);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Player Multiple Vulnerabilities February-2011 (Linux)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0336");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-02.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service.");
  script_tag(name:"affected", value:"Adobe Flash Player versions prior to 10.2.152.26 on Linux");
  script_tag(name:"insight", value:"The flaws are caused by input validation errors, memory corruptions, and
  integer overflow errors when processing malformed Flash content, which could
  be exploited by attackers to execute arbitrary code by tricking a user into
  visiting a specially crafted web page.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 10.2.152.26 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.");

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

if(version_is_less(version:flashVer, test_version:"10.2.152.26")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
