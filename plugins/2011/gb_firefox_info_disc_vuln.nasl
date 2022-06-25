###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_info_disc_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Mozilla Firefox Information Disclosure Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801875");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-1712");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Mozilla Firefox Information Disclosure Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://scarybeastsecurity.blogspot.com/2011/03/multi-browser-heap-address-leak-in-xslt.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain potentially
  sensitive information about heap memory addresses.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.6.16 and prior.");
  script_tag(name:"insight", value:"The flaw is due to an error in txXPathNodeUtils::getXSLTId function
  in txStandaloneXPathTreeWalker.cpp allows remote attackers to obtain
  potentially sensitive information about heap memory addresses via an XML
  document containing a call to the XSLT generate-id XPath function.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 4 or later.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox and is prone to
  information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/new/");
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_is_less_equal(version:ffVer, test_version:"3.6.16")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
