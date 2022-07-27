###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zavio_ip_cameras_multiple_vulns_05_13.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Zavio IP Cameras Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103721");
  script_bugtraq_id(60189, 60191, 60190, 60188);
  script_cve_id("CVE-2013-2567", "CVE-2013-2569", "CVE-2013-2568", "CVE-2013-2570");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11865 $");

  script_name("Zavio IP Cameras Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60189");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60191");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60190");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60188");
  script_xref(name:"URL", value:"http://www.coresecurity.com/advisories/zavio-IP-cameras-multiple-vulnerabilities");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-05-29 16:28:20 +0200 (Wed, 29 May 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Boa/banner");
  script_tag(name:"solution", value:"Update firmware.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Zavio IP Cameras are prone to multiple vulnerabilities.

1. [CVE-2013-2567] to bypass user web interface authentication using hard-coded
   credentials.
2. [CVE-2013-2568] to execute arbitrary commands from the administration web
   interface. This flaw can also be used to obtain all credentials of registered
   users.
3. [CVE-2013-2569] to access the camera video stream.
4. [CVE-2013-2570] to execute arbitrary commands from the administration web
   interface (post authentication only).

Zavio IP Cameras running firmware version 1.6.03 and below are
vulnerable.");
  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner || "Server: Boa/" >!< banner)exit(0);

user = "manufacture";
pass = "erutcafunam";

userpass = string(user,":",pass);
userpass64 = base64(str:userpass);

url = '/cgi-bin/mft/wireless_mft'; # i see a lot of devices dying when trying to run a command. So just check for the auth bypass

req = string("GET ", url," HTTP/1.1\r\n", "Host: ",  get_host_name(),"\r\n\r\n");
resp = http_send_recv(port:port, data:req);

if(resp !~ "HTTP/1.. 401")exit(0);

req = string("GET ", url," HTTP/1.1\r\n",
             "Host: ", get_host_name(),"\r\n",
             "Authorization: Basic ",userpass64,"\r\n",
             "\r\n");

resp = http_send_recv(port:port, data:req);

if(resp =~ "HTTP/1.. 200") {

  security_message(port:port);
  exit(0);

}
