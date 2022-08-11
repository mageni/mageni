##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asus_rt-n10e_router_info_disc_vuln.nasl 32348 2013-10-10 14:55:27Z oct$
#
# ASUS RT-N10E Wireless Router Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803769");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-3610");
  script_bugtraq_id(62850);
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-10 13:46:03 +0530 (Thu, 10 Oct 2013)");
  script_name("ASUS RT-N10E Wireless Router Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running ASUS RT-N10E Wireless Router and is prone to information
  disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Send direct HTTP GET request and check it is possible to read the password
  and other information or not.");
  script_tag(name:"solution", value:"Upgrade to ASUS Wireless-N150 Router RT-N10E firmware 2.0.0.25 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"The flaw is due to the device not properly restricting access to the
  '/qis/QIS_finish.htm' page.");
  script_tag(name:"affected", value:"ASUS Wireless-N150 Router RT-N10E firmware versions 2.0.0.24 and earlier.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to disclose certain
  sensitive information.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55159");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/984366");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("RT-N10E/banner");

  script_xref(name:"URL", value:"http://www.asus.com/Networking/RTN10E/#support_Download");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);

banner = get_http_banner(port: port);
if(banner && 'WWW-Authenticate: Basic realm="RT-N10E"' >!< banner){
  exit(0);
}

url = "/qis/QIS_finish.htm";

if(http_vuln_check(port:port, url:url,
   pattern:"ASUS Wireless Router",
   extra_check:make_list("password_item",
   "account_item", "#wanip_item")))
{
  report = report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}
