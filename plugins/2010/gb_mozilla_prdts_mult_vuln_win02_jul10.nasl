###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win02_jul10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Mozilla Products Multiple Vulnerabilities jul-10 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801387");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_bugtraq_id(41824);
  script_cve_id("CVE-2010-1215", "CVE-2010-1207", "CVE-2010-1210");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Mozilla Products Multiple Vulnerabilities jul-10 (Windows)");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-38.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-43.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-44.html");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service
  or execute arbitrary code or XSS problems.");

  script_tag(name:"affected", value:"Firefox version 3.5.x before 3.5.11 and 3.6.x before 3.6.7
  Thunderbird version 3.1.x before 3.1.1");

  script_tag(name:"insight", value:"The flaws are due to:

  - An error in the handling of 'SJOW()' and 'fast()' native function, when
  content script which is running in a chrome context accesses a content
  object via SJOW.

  - An error in the handling of canvas element, can be used to read data from
  another site, violating the same-origin policy.The read restriction placed
  on a canvas element which has had cross-origin data rendered into it can be
  bypassed by retaining a reference to the canvas element's context and
  deleting the associated canvas node from the DOM.

  - Undefined positions within various 8 bit character encoding's are mapped to
  the sequence U+FFFD which when displayed causes the immediately following
  character to disappear from the text run.");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox/Thunderbird that are prone to
  multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.11 or 3.6.7

  Upgrade to Thunderbird version 3.0.6 or 3.1.1");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.6") ||
     version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.10"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_is_equal(version:tbVer, test_version:"3.1.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
