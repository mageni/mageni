###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cgi_irc_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# CGI:IRC 'nonjs' Interface Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801859");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_cve_id("CVE-2011-0050");
  script_bugtraq_id(46303);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("CGI:IRC 'nonjs' Interface Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43217");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0346");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"CGI:IRC versions prior to 0.5.10.");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input passed via
  the 'R' parameter in the 'nonjs' interface (interfaces/nonjs.pm), that
  allows attackers to execute arbitrary HTML and script code on the web server.");
  script_tag(name:"solution", value:"Upgrade to CGI:IRC version 0.5.10 or later.");
  script_tag(name:"summary", value:"This host is running CGI:IRC and is prone to cross site scripting
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://cgiirc.org/download/");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir (make_list_unique("/cgiirc", cgi_dirs(port:port)))
{

  if( dir == "/" ) dir = "";

  req = http_get(item:dir + "/irc.cgi",  port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if(">CGI:IRC Login<" >< res)
  {
    url = dir + "/irc.cgi?nick=openvas&interface=mozilla&R=<script>alert" +
                "('openvas-xss-test')</script>&item=fwindowlist";

    if(http_vuln_check(port:port, url:url, check_header: TRUE,
                       pattern:"<script>alert\('openvas-xss-test'\)</script>"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);