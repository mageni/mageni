###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_clickjacking_vuln_win.nasl 11861 2018-10-12 09:29:59Z cfischer $
#
# Mozilla Products Certificate Page Clickjacking Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802893");
  script_version("$Revision: 11861 $");
  script_cve_id("CVE-2012-1964");
  script_bugtraq_id(54581);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:29:59 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-23 18:40:44 +0530 (Mon, 23 Jul 2012)");
  script_name("Mozilla Products Certificate Page Clickjacking Vulnerability (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49965");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027256");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027257");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-54.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to gain sensitive information
  or bypass certain security restrictions.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.10
  Thunderbird version 5.0 through 12.0
  Mozilla Firefox version 4.x through 12.0
  Thunderbird ESR version 10.x before 10.0.6
  Mozilla Firefox ESR version 10.x before 10.0.6 on Windows");
  script_tag(name:"insight", value:"The certificate warning functionality in
  browser/components/certerror/content/aboutCertError.xhtml fails to handle
  attempted clickjacking of the 'about:certerror' page, allowing
  man-in-the-middle attackers to trick users into adding an unintended
  exception via an IFRAME element");
  script_tag(name:"summary", value:"This host is installed with Mozilla firefox/thunderbird/seamonkey and is
  prone to clickjacking vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 14.0 or ESR version 10.0.6 or later, upgrade to SeaMonkey version to 2.11 or later,
  upgrade to Thunderbird version to 14.0 or ESR 10.0.6 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");
  script_xref(name:"URL", value:"http://www.mozilla.org/en-US/thunderbird/");

  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"10.0.5")||
     version_in_range(version:ffVer, test_version:"11.0", test_version2:"12.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

seaVer = get_kb_item("Seamonkey/Win/Ver");
if(seaVer)
{
  if(version_is_less(version:seaVer, test_version:"2.10"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_in_range(version:tbVer, test_version:"5.0", test_version2:"10.0.5")||
     version_in_range(version:tbVer, test_version:"11.0", test_version2:"12.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
