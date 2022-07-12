###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asus_rt-n56u_49308.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# ASUS RT-N56U Wireless Router 'QIS_wizard.htm' Password Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103228");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-4497");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:51:18 +0200 (Fri, 26 Aug 2011)");
  script_bugtraq_id(49308);
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_name("ASUS RT-N56U Wireless Router 'QIS_wizard.htm' Password Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49308");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/200814");
  script_xref(name:"URL", value:"http://www.asus.com/Networks/Wireless_Routers/RTN56U/");
  script_xref(name:"URL", value:"http://www.asus.com/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RT-N56U/banner");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"ASUS RT-N56U wireless router is prone to an information-disclosure
vulnerability that exposes sensitive information.

Successful exploits will allow unauthenticated attackers to obtain
sensitive information of the device such as administrative password,
which may aid in further attacks.

ASUS RT-N56U firmware version 1.0.1.4 is vulnerable.");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner || 'Basic realm="RT-N56U"' >!< banner)exit(0);

url = string("/QIS_wizard.htm?flag=detect.");

if(http_vuln_check(port:port, url:url,pattern:"<title>ASUS Wireless Router RT-N56U - Quickly Internet Setup")) {

  security_message(port:port);
  exit(0);

}

exit(0);

