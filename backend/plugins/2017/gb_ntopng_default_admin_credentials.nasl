###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntopng_default_admin_credentials.nasl 11025 2018-08-17 08:27:37Z cfischer $
#
# ntopng Default Admin Credentials Check
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

CPE = 'cpe:/a:ntop:ntopng';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112078");
  script_version("$Revision: 11025 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 10:27:37 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-10-11 10:51:21 +0200 (Wed, 11 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("ntopng Default Admin Credentials Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_ntopng_detect.nasl");
  script_require_ports("Services/www", 3000);
  script_mandatory_keys("ntopng/installed");

  script_tag(name:"summary", value:"ntopng is prone to a default account authentication bypass vulnerability.");
  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to sensitive information.");
  script_tag(name:"vuldetect", value:"This script tries to login with default credentials.");
  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
get_app_location(cpe:CPE, port:port, nofork:TRUE); # To have a reference to the Detection-NVT

host = http_host_name(port:port);

data = string("user=admin&password=admin&referer=" + host + "%2Fauthorize.html");

req = http_post_req(port:port, url:'/authorize.html', data:data,
  add_headers:make_array('Content-Type', 'application/x-www-form-urlencoded'),
  accept_headers:'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
res = http_keepalive_send_recv(port:port, data:req);

cookie = eregmatch( pattern:"Set-Cookie: session=([0-9a-zA-Z]+)", string:res);

if(isnull(cookie[1])) exit(0);

req = http_get_req(port:port, url:'/',
  add_headers:make_array('Cookie', 'session=' + cookie[1] + '; user=admin'),
  accept_headers:'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8');
res = http_keepalive_send_recv(port:port, data:req);

if('<li><a href="/lua/logout.lua"><i class="fa fa-sign-out"></i> Logout admin</a></li>' >< res
  && '<a href="/lua/admin/users.lua"><span class="label label-primary">admin</span></a>' >< res) {
  security_message(port:port, data:'It was possible to login with the following default credentials Username: "admin" & Password: "admin"');
  exit(0);
}

exit(99);
