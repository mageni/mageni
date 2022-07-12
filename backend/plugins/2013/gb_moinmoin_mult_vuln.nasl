###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moinmoin_mult_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# MoinMoin Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:moinmo:moinmoin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803445");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2012-6080", "CVE-2012-6081", "CVE-2012-6082", "CVE-2012-6495");
  script_bugtraq_id(57076, 57082, 57089, 57147);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-21 15:03:34 +0530 (Thu, 21 Mar 2013)");
  script_name("MoinMoin Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("moinmoinWiki/installed");

  script_xref(name:"URL", value:"http://moinmo.in/SecurityFixes");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51663");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/12/29/6");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/12/30/6");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  HTML or web script in a user's browser session in the context of an affected
  site, uplaod malicious script and overwrite arbitrary files via directory
  traversal sequences.");
  script_tag(name:"affected", value:"MoinMoin version 1.9.x prior to 1.9.6");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - Certain input when handling the AttachFile action is not properly verified
    before being used to write files.

  - The application allows the upload of files with arbitrary extensions to a
    folder inside the webroot when handling the twikidraw or anywikidraw
    actions.

  - Input passed via page name in rss link is not properly sanitised before
    being displayed to the user.");
  script_tag(name:"solution", value:"Update to MoinMoin 1.9.6 or later.");
  script_tag(name:"summary", value:"This host is installed with MoinMoin and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://moinmo.in/MoinMoinDownload");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( port:port, cpe:CPE ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + 'MoinMoin/theme/__init__.py/"<script>alert(document.cookie)</script>';

if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(document\.cookie\)</script>", check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );