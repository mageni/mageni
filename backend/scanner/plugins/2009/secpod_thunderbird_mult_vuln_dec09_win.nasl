###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_thunderbird_mult_vuln_dec09_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Thunderbird Multiple Vulnerabilities Dec-09 (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902004");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3981", "CVE-2009-3982");
  script_bugtraq_id(37361, 37362, 37363, 37364);
  script_name("Thunderbird Multiple Vulnerabilities Dec-09 (Windows)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code via
  unknown vectors or compromise a user's system.");
  script_tag(name:"affected", value:"Thunderbird version 3.0 and prior on Windows.");
  script_tag(name:"insight", value:"Memory corruption error due to multiple unspecified flaws in the browser
  engine, which can be exploited via unknown vectors.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 3.0.1 or later.");
  script_tag(name:"summary", value:"The host is installed with Thunderbird and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37699");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3547");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-65.html");
  script_xref(name:"URL", value:"http://www.mozillamessaging.com/en-US/thunderbird/");
  exit(0);
}


include("version_func.inc");

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_is_less_equal(version:tbVer, test_version:"3.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
