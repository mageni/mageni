###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avigilon_camera_default_credentials.nasl 11328 2018-09-11 12:32:47Z tpassfeld $
#
# Avigilon Camera Default Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.114026");
  script_version("$Revision: 11328 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 14:32:47 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-08-28 15:52:48 +0200 (Tue, 28 Aug 2018)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Avigilon Camera Default Credentials");
  script_dependencies("gb_avigilon_camera_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("avigilon/camera/detected");

  script_xref(name:"URL", value:"https://customvideosecurity.com/blog/tag/default-password-axis/");

  script_tag(name:"summary", value:"The remote Avigilon Camera is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Avigilon Camera is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Avigilon Camera is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

CPE = "cpe:/a:avigilon:avigilon_camera";

if(!port = get_app_port(cpe: CPE)) exit(0);

#Same credentials as in 2018/videoiq/gb_videoiq_camera_default_credentials.nasl,
#because the software is heavily based on VideoIQ.
username = "supervisor";
password = "supervisor";

#Url for sessionID extraction, which is needed for login
url1 = "/";

req1 = http_get(port: port, item: url1);
res1 = http_keepalive_send_recv(port: port, data: req1);

sessionID = eregmatch(pattern: "JSESSIONID=([0-9a-zA-Z]+)", string: res1);

if(!sessionID[0]) exit(0);

url2 = "/;" + sessionID[0] + "?wicket:bookmarkablePage=:com.videoiq.fusion.camerawebapi.ui.pages.LoginPage&wicket:interface=:0:loginPanel:loginForm::IFormSubmitListener::";

data = "loginForm1_hf_0=&userName=" + username + "&password=" + password  + "&login=";

req = http_post_req(port: port,
                    url: url2,
                    data: data,
                    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded",
                                            "Cookie", sessionID[0]));

res2 = http_keepalive_send_recv(port: port, data: req);

#If the login was successful, the server responds pretty much only with the sessionID from before.

res2SessionID = eregmatch(pattern: "JSESSIONID=([0-9a-zA-Z]+)", string: res2);

if(res2SessionID[0] && res2SessionID[0] == sessionID[0]) {
  report = 'It was possible to login via the default username "' + username + '" and the default password "' + password + '".';

  security_message(port: port, data: report);
  exit(0);
}

exit(99);
