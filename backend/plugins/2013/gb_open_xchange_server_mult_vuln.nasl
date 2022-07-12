###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_xchange_server_mult_vuln.nasl 11866 2018-10-12 10:12:29Z cfischer $
#
# Open-Xchange Server Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.803182");
  script_version("$Revision: 11866 $");
  script_cve_id("CVE-2013-1646", "CVE-2013-1647", "CVE-2013-1648", "CVE-2013-1650",
                "CVE-2013-1651");
  script_bugtraq_id(58465, 58473, 58475, 58469, 58470);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:12:29 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-18 10:14:58 +0530 (Mon, 18 Mar 2013)");
  script_name("Open-Xchange Server Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52603");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Mar/74");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24791");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120785");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("find_service.nasl", "http_version.nasl");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or
  web script in a user's browser session in context of an affected site,
  compromise the application and access or modify data in the database.");
  script_tag(name:"affected", value:"Open-Xchange Server versions prior to 6.20.7-rev14, 6.22.0-rev13
  and 6.22.1-rev14.");
  script_tag(name:"insight", value:"- Input passed via arbitrary GET parameters to /servlet/TestServlet is not
    properly sanitized before being returned to the user.

  - Input related to the 'Source' field when creating subscriptions is not
    properly sanitized before being used. This can be exploited to perform
    arbitrary HTTP GET requests to remote and local servers.

  - The OXUpdater component does not properly validate the SSL certificate of
    an update server. This can be exploited to spoof update packages via a
    MitM (Man-in-the-Middle) attack.

  - The application creates the /opt/open-exchange/etc directory with insecure
    world-readable permissions. This can be exploited to disclose certain
    sensitive information.

  - Input passed via the 'location' GET parameter to /ajax/redirect is not
    properly sanitized before being used to construct HTTP response headers.

  - Certain input related to RSS feed contents is not properly sanitized before
    being used. This can be exploited to insert arbitrary HTML and script code.");
  script_tag(name:"solution", value:"Update to versions 6.20.7-rev14, 6.22.0-rev13, or 6.22.1-rev14.");
  script_tag(name:"summary", value:"This host is running Open-Xchange Server and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.open-xchange.com/home.html");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/ox6", "/Open-Xchange", cgi_dirs(port:port)))
{

  if( dir == "/" ) dir = "";

  ## Request for the index.php
  sndReq = http_get(item:dir + "/ox.html", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if(">Open-Xchange Server<" >< rcvRes)
  {
    url = dir + "/servlet/TestServlet?foo=<script>alert(document.cookie)</script>";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
             pattern:"<script>alert\(document.cookie\)</script>"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);