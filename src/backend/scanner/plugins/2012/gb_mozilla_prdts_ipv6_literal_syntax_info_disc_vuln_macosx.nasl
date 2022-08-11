###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_ipv6_literal_syntax_info_disc_vuln_macosx.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Mozilla Products IPv6 Literal Syntax Cross Domain Information Disclosure Vulnerability (MAC OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802583");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2011-3670");
  script_bugtraq_id(51786);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-03 17:51:59 +0530 (Fri, 03 Feb 2012)");
  script_name("Mozilla Products IPv6 Literal Syntax Cross Domain Information Disclosure Vulnerability (MAC OS X)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47839/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026613");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-02.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to get sensitive information.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.4
  Thunderbird version before 3.1.18 and 5.0 through 6.0.
  Mozilla Firefox version before 3.6.26 and 4.x through 6.0");
  script_tag(name:"insight", value:"The flaw is due to requests made using IPv6 syntax using XMLHttpRequest
  objects through a proxy may generate errors depending on proxy configuration
  for IPv6. The resulting error messages from the proxy may disclose sensitive
  data.");
  script_tag(name:"summary", value:"The host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to information disclosure vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.27 or 7.0 or later.

  Upgrade to SeaMonkey version to 2.4 or later.

  Upgrade to Thunderbird version to 3.1.18 or 7.0 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(!isnull(ffVer))
{
  if(version_is_less(version:ffVer, test_version:"3.6.26") ||
     version_in_range(version:ffVer, test_version:"4.0", test_version2:"6.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

seaVer = get_kb_item("SeaMonkey/MacOSX/Version");
if(!isnull(seaVer))
{
  if(version_is_less(version:seaVer, test_version:"2.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("ThunderBird/MacOSX/Version");
if(!isnull(tbVer))
{
  if(version_is_less(version:tbVer, test_version:"3.1.18") ||
     version_in_range(version:tbVer, test_version:"5.0", test_version2:"6.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
