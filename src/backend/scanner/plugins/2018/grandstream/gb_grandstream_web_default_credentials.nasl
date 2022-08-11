###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_grandstream_web_default_credentials.nasl 11328 2018-09-11 12:32:47Z tpassfeld $
#
# Grandstream Web UI Default Credentials
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114019");
  script_version("$Revision: 11328 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 14:32:47 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-08-08 13:17:57 +0200 (Wed, 08 Aug 2018)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Grandstream Web UI Default Credentials");
  script_dependencies("gb_grandstream_web_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("grandstream/webui/detected");

  script_xref(name:"URL", value:"https://cirt.net/passwords");

  script_tag(name:"summary", value:"The remote Grandstream Web UI is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Grandstream Web UI is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Grandstream Web UI is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

CPE = "cpe:/a:grandstream:web_ui";

if(!port = get_app_port(cpe: CPE)) exit(0);

#Url for sessionID extraction(needed for certain versions with a slightly different way to log in).
#Version is unknown at this point(requires login), so differentiation is impossible.
url1 = "/cgi-bin/login";
#Url for the actual login
url2 = "/cgi-bin/dologin";

res1 = http_get_cache(port: port, item: url1);

sessionToken = eregmatch(pattern: '<input name=\"session_token\" type=hidden value=\"([0-9a-zA-Z]+)\">', string: res1);

if(sessionToken[1]) {
  sessionID = sessionToken[1];
}

loginTypes = make_list(0, 1);

foreach loginType (loginTypes) {
  if(!loginType) {
    data = "session_token=" + sessionID + "&username=admin&P2=admin&Login=Login&gnkey=0b82";
  }
  else {
    data = "P2=123&Login=Login&gnkey=0b82";
  }
  req = http_post_req(port: port,
                      url: url2,
                      data: data,
                      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));

  res = http_keepalive_send_recv(port: port, data: req);

  if("<b>Software Version: </b>" >< res || "<b>BASIC SETTINGS</b>" >< res || "<b>ADVANCED SETTINGS</b>" >< res) {
    #Program-- 1.0.6.13
    vers = eregmatch(pattern: "Program\s*--\s*([0-9.]+)", string: res);
    if(vers[1]) {
      version = vers[1];
      set_kb_item(name: "grandstream/webui/version", value: version);
    }
    if(!loginType) {
      report = 'It was possible to login via the default admin password "admin".';
    }
    else {
      report = 'It was possible to login via the default user password "123".';
      #Now checking if you can also log in as an administrator
      url3 = "/cgi-bin/doadminlogin";
      data = "P2=admin&Login=Login&gnkey=0b82";
      req = http_post_req(port: port,
                          url: url3,
                          data: data,
                          add_headers: make_array("Content-Type", "application/x-www-form-urlencoded",
                                                  "Cookie", "session_id=" + sessionID));

      res = http_keepalive_send_recv(port: port, data: req);

      if("<b>Admin Password: </b>" >< res || "<i>Keep-alive Interval: </i>" >< res || "<i>ACS Username: </i>" >< res
         || '<input type="submit" name="update"' >< res || '<input type="submit" name="apply"' >< res) {
        report += '\r\nIt was also possible to login via the default admin password "admin".';
      }
    }
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
