###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_csrf_vuln_feb14_macosx.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Google Chrome Cross-Site Request Forgery (CSRF) Vulnerability (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804317");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-6166");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-17 17:40:48 +0530 (Mon, 17 Feb 2014)");
  script_name("Google Chrome Cross-Site Request Forgery (CSRF) Vulnerability (Mac OS X)");


  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to cross-site request
forgery attack.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to improper validation of 'HTTP Cookie headers' for
restricted character-set.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct the
equivalent of a persistent Logout cross-site request forgery (CSRF) attack.");
  script_tag(name:"affected", value:"Google Chrome version prior to 29 on Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 29 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q4/117");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/04/03/10");
  script_xref(name:"URL", value:"https://code.google.com/p/chromium/issues/detail?id=238041");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"29.0"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
