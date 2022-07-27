###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_seamonkey_mult_vuln_dec09_win.nasl 12670 2018-12-05 14:14:20Z cfischer $
#
# Seamonkey Multiple Vulnerabilities Dec-09 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902003");
  script_version("$Revision: 12670 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 15:14:20 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3388", "CVE-2009-3389", "CVE-2009-3979", "CVE-2009-3980",
                "CVE-2009-3981", "CVE-2009-3982", "CVE-2009-3983", "CVE-2009-3984",
                "CVE-2009-3985", "CVE-2009-3986", "CVE-2009-3987");
  script_bugtraq_id(37369, 37368, 37361, 37362, 37363, 37364, 37366, 37367, 37370,
                    37365, 37360);
  script_name("Seamonkey Multiple Vulnerabilities Dec-09 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37699");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3547");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-65.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-66.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-67.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-68.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-69.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-70.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-71.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct spoofing attacks,
  bypass certain security restrictions, manipulate certain data, disclose
  sensitive information, or compromise a user's system.");

  script_tag(name:"affected", value:"Seamonkey version prior to 2.0.1 on Windows.");

  script_tag(name:"insight", value:"For more information about vulnerabilities on Seamonkey, refer the links
  mentioned in references.");

  script_tag(name:"solution", value:"Upgrade to Seamonkey version 2.0.1.");

  script_tag(name:"summary", value:"The host is installed with Seamonkey and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"2.0.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
