###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_shockwave_player_mult_vuln_aug10.nasl 14331 2019-03-19 14:03:05Z jschulte $
#
# Adobe Shockwave Player Multiple Vulnerabilities Aug-10
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
  script_oid("1.3.6.1.4.1.25623.1.0.902237");
  script_version("$Revision: 14331 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:03:05 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_cve_id("CVE-2010-2863", "CVE-2010-2864", "CVE-2010-2865", "CVE-2010-2866",
                "CVE-2010-2867", "CVE-2010-2868", "CVE-2010-2869", "CVE-2010-2870",
                "CVE-2010-2871", "CVE-2010-2872", "CVE-2010-2873", "CVE-2010-2874",
                "CVE-2010-2875", "CVE-2010-2876", "CVE-2010-2877", "CVE-2010-2878",
                "CVE-2010-2879", "CVE-2010-2880", "CVE-2010-2881", "CVE-2010-2882");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities Aug-10");
  script_xref(name:"URL", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-13");
  script_xref(name:"URL", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-14");
  script_xref(name:"URL", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-15");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-161/");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-20.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/513299/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/513334/100/0/threaded");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code in
  the context of the affected application.");
  script_tag(name:"affected", value:"Adobe Shockwave Player prior to 11.5.8.612 on Windows");
  script_tag(name:"insight", value:"Multiple memory corruption vulnerabilities are present in the application.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player 11.5.8.612");
  script_tag(name:"summary", value:"This host is installed with Adobe Shockwave Player and is prone
  to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less(version:shockVer, test_version:"11.5.8.612")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
