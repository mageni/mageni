###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_sec_bypass_vuln_may12_macosx.nasl 11861 2018-10-12 09:29:59Z cfischer $
#
# Mozilla Products Security Bypass Vulnerability - May12 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802843");
  script_version("$Revision: 11861 $");
  script_cve_id("CVE-2012-0475");
  script_bugtraq_id(53230);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:29:59 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-05-02 12:29:17 +0530 (Wed, 02 May 2012)");
  script_name("Mozilla Products Security Bypass Vulnerability - May12 (Mac OS X)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48972/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48932/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026971");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-28.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject scripts or bypass
  certain security restrictions.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.9
  Thunderbird version 5.0 through 11.0
  Mozilla Firefox version 4.x through 11.0");
  script_tag(name:"insight", value:"The flaw is due to an error within the handling of XMLHttpRequest
  and WebSocket while using an IPv6 address can be exploited to bypass the
  same origin policy.");
  script_tag(name:"summary", value:"This host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to security bypass vulnerability");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 12.0 or later, upgrade to SeaMonkey version to 2.9 or later,
  upgrade to Thunderbird version to 12.0 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");
  script_xref(name:"URL", value:"http://www.mozilla.org/en-US/thunderbird/");
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(!isnull(ffVer))
{
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"11.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

seaVer = get_kb_item("SeaMonkey/MacOSX/Version");

if(!isnull(seaVer))
{
  if(version_is_less(version:seaVer, test_version:"2.9"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("ThunderBird/MacOSX/Version");

if(!isnull(tbVer))
{
  if(version_in_range(version:tbVer, test_version:"5.0", test_version2:"11.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
