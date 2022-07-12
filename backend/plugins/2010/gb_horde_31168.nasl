###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_31168.nasl 12020 2018-10-22 14:26:09Z cfischer $
#
# Horde Turba Contact Manager '/imp/test.php' Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:horde:imp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100724");
  script_version("$Revision: 12020 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 16:26:09 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2010-07-27 20:48:46 +0200 (Tue, 27 Jul 2010)");
  script_bugtraq_id(31168);
  script_cve_id("CVE-2008-4182");
  script_name("Horde Turba Contact Manager '/imp/test.php' Cross Site Scripting Vulnerability");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("imp_detect.nasl");
  script_mandatory_keys("horde/imp/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/31168");
  script_xref(name:"URL", value:"http://www.horde.org/turba/");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Turba Contact Manager is prone to a cross-site scripting vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may let the attacker
  steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Turba Contact Manager H3 2.2.1 is vulnerable. Other versions may also
  be affected.

  Note that this issue also affects Turba on Horde IMP.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
ex = "server=%3Cscript%3Ealert%28%27vt-xss-test%27%29%3C%2Fscript%3E&port=1&user=2&passwd=3&server_type=imap&f_submit=Submit";
url = dir + "/test.php";

host = http_host_name( port:port );

req = string("POST ", url, " HTTP/1.1\r\n",
  	     "Host: ", host, "\r\n",
	     "Accept-Encoding: identity\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
	     "Content-Length: ", strlen(ex),
	     "\r\n\r\n",
	     ex);
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( ! res ) exit( 0 );

if( res =~ "^HTTP/1\.[01] 200" && egrep( pattern:"<script>alert\('vt-xss-test'\)</script>", string:res, icase:TRUE ) ) {
  report = report_vuln_url( url:url, port:port );
  security_message( port:port, data:url );
}

exit( 0 );