###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win_feb12.nasl 11818 2018-10-10 11:35:42Z asteins $
#
# Mozilla Products Multiple Unspecified Vulnerabilities - Feb12 (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802580");
  script_version("$Revision: 11818 $");
  script_cve_id("CVE-2012-0442", "CVE-2012-0444", "CVE-2012-0449", "CVE-2011-3659");
  script_bugtraq_id(51756, 51753, 51754, 51755);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 13:35:42 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-03 19:24:43 +0530 (Fri, 03 Feb 2012)");
  script_name("Mozilla Products Multiple Unspecified Vulnerabilities - Feb12 (Windows)");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-08.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-07.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-04.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl",
                      "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service or
  possibly execute arbitrary code via unknown vectors.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.7
  Thunderbird version before 3.1.18 and 5.0 through 9.0
  Mozilla Firefox version before 3.6.26 and 4.x through 9.0");
  script_tag(name:"insight", value:"The flaws are due to

  - Multiple unspecified vulnerabilities in the browser engine.

  - An error while initializing nsChildView data structures.

  - Premature notification of AttributeChildRemoved, the removed child nodes
    of nsDOMAttribute can be accessed under certain circumstances.

  - An error while processing a malformed embedded XSLT stylesheet, leads to
    crash the application");
  script_tag(name:"summary", value:"The host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.26 or 10.0 or later.

  Upgrade to SeaMonkey version to 2.7 or later.

  Upgrade to Thunderbird version to 3.1.18 or 10.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");
  script_xref(name:"URL", value:"http://www.mozilla.org/en-US/thunderbird/");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!isnull(ffVer))
{
  if(version_is_less(version:ffVer, test_version:"3.6.26") ||
     version_in_range(version:ffVer, test_version:"4.0", test_version2:"9.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

seaVer = get_kb_item("Seamonkey/Win/Ver");
if(!isnull(seaVer))
{
  if(version_is_less(version:seaVer, test_version:"2.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(!isnull(tbVer))
{
  if(version_is_less(version:tbVer, test_version:"3.1.18") ||
     version_in_range(version:tbVer, test_version:"5.0", test_version2:"9.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
