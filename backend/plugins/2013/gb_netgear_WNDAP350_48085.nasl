###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_WNDAP350_48085.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# NetGear WNDAP350 Wireless Access Point Multiple Information Disclosure Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103702");
  script_bugtraq_id(48085);
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("NetGear WNDAP350 Wireless Access Point Multiple Information Disclosure Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48085");
  script_xref(name:"URL", value:"http://www.netgear.com/");
  script_xref(name:"URL", value:"https://revspace.nl/RevelationSpace/NewsItem11x05x30x0");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-04-22 13:20:27 +0200 (Mon, 22 Apr 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"NetGear WNDAP350 wireless access point is prone to multiple remote information-
disclosure issues because it fails to restrict access to sensitive
information.

A remote attacker can exploit these issues to obtain sensitive
information that can aid in launching further attacks.

WNDAP350 with firmware 2.0.1 and 2.0.9 are vulnerable. Other firmware
versions may also be affected.");
  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(http_vuln_check(port:port, url:"/index.php?page=master", pattern:"<title>Netgear")) {

  url = '/downloadFile.php';

  if(http_vuln_check(port:port, url:url, pattern:"system:basicSettings:adminPasswd")) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

exit(0);
