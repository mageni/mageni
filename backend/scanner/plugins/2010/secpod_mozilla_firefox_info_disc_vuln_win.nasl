###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_firefox_info_disc_vuln_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Mozilla Firefox Information Disclosure Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902305");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-3171", "CVE-2010-3399");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Mozilla Firefox Information Disclosure Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2010-09/0117.html");
  script_xref(name:"URL", value:"http://www.trusteer.com/sites/default/files/Cross_domain_Math_Random_leakage_in_FF_3.6.4-3.6.8.pdf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to bypass the same-origin policy
  and obtain potentially sensitive information. Other attacks are possible.");

  script_tag(name:"affected", value:"Firefox version 3.5.10 through 3.5.11

  Firefox version 3.6.4 through 3.6.8 and 4.0 Beta1");

  script_tag(name:"insight", value:"The flaws are due to:

  - Error in 'Math.random' function in the JavaScript implementation which uses
  a random number generator that is seeded only once per document object, which
  makes it easier for remote attackers to track a user, or trick a user into
  acting upon a spoofed pop-up message, by calculating the seed value.

  - Error in 'js_InitRandom' function in the JavaScript implementation uses a
  context pointer in conjunction with its successor pointer for seeding of a
  random number generator, which makes it easier for remote attackers to guess
  the seed value via a brute-force attack.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.9 or later, 3.5.12 or later, 4.0 Beta-2 or later.");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox and is prone to Information
  Disclosure Vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.5.10", test_version2:"3.5.11")||
     version_in_range(version:ffVer, test_version:"3.6.4", test_version2:"3.6.8")||
     version_is_equal(version:ffVer, test_version:"4.0.b1")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}