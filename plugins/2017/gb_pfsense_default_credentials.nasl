###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pfsense_default_credentials.nasl 13679 2019-02-15 08:20:11Z cfischer $ # auto-updated by SVN
#
# pfSense Default Admin Credentials
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

CPE = 'cpe:/a:pfsense:pfsense';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112122");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-11-14 10:54:12 +0100 (Tue, 14 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("pfSense Default Admin Credentials");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_pfsense_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("pfsense/installed");

  script_tag(name:"solution", value:"Change the passwords.");
  script_tag(name:"summary", value:"In pfSense it is possible to gain administrative access via default credentials.");
  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to sensitive information.");
  script_tag(name:"insight", value:"By convention, each time you create a new instance of pfSense, the admin user is being created with default credentials:
  Username: admin, Password: pfsense.");

  script_xref(name:"URL", value:"https://doc.pfsense.org/index.php/Installing_pfSense#pfSense_Default_Configuration");
  script_xref(name:"URL", value:"https://doc.pfsense.org/index.php/What_is_the_default_username_and_password");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www")) exit(0);
get_app_location(cpe:CPE, port:port, nofork:TRUE); # To have a reference to the detection NVT

req_1 = http_get(port:port, item:"/");
res_1 = http_keepalive_send_recv(port:port, data:req_1, bodyonly:FALSE);

# Grabbing the CSRF-token and -variable to avoid being blocked by CSRF protection
if(magic_token = eregmatch(pattern:'var csrfMagicToken = "(.*)";var csrfMagicName', string:res_1, icase:TRUE)) {
  magic_token = urlencode(str:magic_token[1]);
}

if(magic_var = eregmatch(pattern:'var csrfMagicName = "(.*)";</script>', string:res_1, icase:TRUE)) {
  magic_var = magic_var[1];
} else {
  magic_var = '__csrf_magic';
}

cookie_1 = http_get_cookie_from_header(buf:res_1, pattern:'Set-Cookie: (.*); path=/');
data = magic_var + '=' + magic_token + '&usernamefld=admin&passwordfld=pfsense&login=Sign+In';
accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8';

# In order to avoid being blocked by DNS Rebind Protection (e.g. if it is misconfigured), the Host Name is being replaced with the Host IP
req_2 = http_post_req(port:port, url:"/", data:data, accept_header:accept, host_header_use_ip:TRUE,
                      add_headers:make_array("Upgrade-Insecure-Requests", "1", "Cookie", cookie_1, "Content-Type", "application/x-www-form-urlencoded"));
res_2 = http_keepalive_send_recv(port:port, data:req_2, bodyonly:FALSE);

# Another cookie is set by the application and therefore being obtained since the POST response is an HTTP redirect (302)
cookie_2 = http_get_cookie_from_header(buf:res_2, pattern:'Set-Cookie: (.*); path=/');

# Again, the DNS Rebind Protection needs to be avoided, so the Host IP is needed for a valid GET request
req_3 = http_get_req(port:port, url:"/", add_headers:make_array("Cookie", cookie_2), accept_header:accept, host_header_use_ip:TRUE);
res_3 = http_keepalive_send_recv(port:port, data:req_3, bodyonly:FALSE);

if("Status: Dashboard</title>" >< res_3) {
  report = 'It was possible to authenticate with the following credentials:\n\nUsername: admin\nPassword: pfsense';
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
