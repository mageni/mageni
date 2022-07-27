###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari Multiple Vulnerabilities - Aug09
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900912");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-08-19 06:49:38 +0200 (Wed, 19 Aug 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2195", "CVE-2009-2196", "CVE-2009-2199",
                "CVE-2009-2200");
  script_bugtraq_id(36022, 36023, 36024, 36026);
  script_name("Apple Safari Multiple Vulnerabilities - Aug09");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3733");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36269/");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2009/Aug/msg00002.html");
  script_xref(name:"URL", value:"http://securethoughts.com/2009/08/hijacking-safari-4-top-sites-with-phish-bombs");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code, bypass
  security restrictions, gain sensitive information and can cause Denial of
  Service.");
  script_tag(name:"affected", value:"Apple Safari version prior to 4.0.3.");
  script_tag(name:"insight", value:"- An error in WebKit while parsing malicious floating point numbers can be
    exploited to cause buffer overflows.

  - An unspecified error in the Top Sites feature can be exploited to place a
    malicious  web site in the Top Sites view when a user visits a specially
    crafted web page.

  - Incomplete blacklist vulnerability in WebKit can be exploited via
    unspecified homoglyphs.

  - An error in WebKit in the handling of the 'pluginspage' attribute of the
    'embed' element can be exploited to launch arbitrary file: URLs and obtain
    sensitive information via a crafted HTML document.");
  script_tag(name:"solution", value:"Upgrade to Safari version 4.0.3.");
  script_tag(name:"summary", value:"This host is installed with Apple Safari Web Browser and is prone
  to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer)
  exit(0);

if(version_is_less(version:safariVer, test_version:"4.31.9.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
