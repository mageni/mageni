###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RaidSonic_57958.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# RaidSonic IB-NAS5220 and IB-NAS4220-B Multiple Security Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103663");
  script_bugtraq_id(57958);
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_name("RaidSonic IB-NAS5220 and IB-NAS4220-B Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57958");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-02-18 16:02:12 +0100 (Mon, 18 Feb 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"RaidSonic IB-NAS5220 and IB-NAS422-B are prone to multiple security
vulnerabilities, including:

1. An authentication-bypass vulnerability

2. An HTML-injection vulnerability

3. A command-injection vulnerability

The attacker may leverage these issues to bypass certain security
restrictions and perform unauthorized actions or execute HTML and
script code in the context of the affected browser, potentially
allowing the attacker to steal cookie-based authentication
credentials, control how the site is rendered to the user, or inject
and execute arbitrary commands.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

url = '/login.cgi';
if(http_vuln_check(port:port, url:url,pattern:"<title>IB-NAS",check_header:TRUE, usecache:TRUE)) {

  url = '/cgi/user/user.cgi';
  if(http_vuln_check(port:port, url:url,pattern:"<option>admin</option>",check_header:TRUE)) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
