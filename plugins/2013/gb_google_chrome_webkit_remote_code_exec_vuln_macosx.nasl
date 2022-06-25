###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_webkit_remote_code_exec_vuln_macosx.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Google Chrome Webkit Remote Code Execution Vulnerability (MAC OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803623");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-0912");
  script_bugtraq_id(58388);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-05-28 17:20:48 +0530 (Tue, 28 May 2013)");
  script_name("Google Chrome Webkit Remote Code Execution Vulnerability (MAC OS X)");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52534");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/03/stable-channel-update_7.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will let the attackers to execute arbitrary code via
  crafted SVG document.");
  script_tag(name:"affected", value:"Google Chrome version prior to 25.0.1364.160 on MAC OS X");
  script_tag(name:"insight", value:"WebKit contains a type confusion flaw in the 'SVGViewSpec::viewTarget'
  function in WebCore/svg/SVGViewSpec.cpp when handling non-SVG elements.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 25.0.1364.160 or later.");
  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to remote
  code execution vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"25.0.1364.160"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
