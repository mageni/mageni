###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_schneider_modicon_m340_default_web_credential.nasl 11103 2018-08-24 10:37:26Z mmartin $
#
# Schneider Modicon M340 Default Credentials
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
# of the License, or (at your option) any later version
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
CPE = 'cpe:/h:schneider-electric:modicon_m340';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103857");
  script_version("$Revision: 11103 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-08-24 12:37:26 +0200 (Fri, 24 Aug 2018) $");
  script_tag(name:"creation_date", value:"2013-12-16 11:44:04 +0200 (Mon, 16 Dec 2013)");
  script_name("Schneider Modicon M340 Default Credentials");

  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2013/12/08/schneider-modicon-m340-for-ethernet-multiple-default-credentials/");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_schneider_modicon_m340_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("schneider_modicon_m340/installed");

  script_tag(name:"solution", value:"Change the password.");
  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"summary", value:"The remote Schneider Modicon M340  is prone to a
default account authentication bypass vulnerability. This issue may
be exploited by a remote attacker to gain access to sensitive
information or modify system configuration.

It was possible to login as user 'USER' with password 'USER'.");

 exit(0);

}

include("misc_func.inc");
include("http_func.inc");

include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);

url = '/secure/embedded/http_passwd_config.htm?Language=English';

req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf !~ "HTTP/1\.. 401" || "WWW-Authenticate" >!< buf)exit(0);

auth = base64(str:'USER:USER');

req = ereg_replace(string:req, pattern:'\r\n\r\n', replace:'\r\nAuthorization: Basic ' + auth + '\r\n\r\n\r\n');
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf =~ 'HTTP/1.. 200' && '<title>Passwords modification' >< buf) {
  security_message(port:port);
  exit(0);
}

exit(99);
