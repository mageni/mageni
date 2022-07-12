###############################################################################
# OpenVAS Vulnerability Test
# $Id: hp_power_manager_default_credentials.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# HP Power Manager Management Web Server Login Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:hp:power_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100350");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-11-18 12:44:57 +0100 (Wed, 18 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("HP Power Manager Management default credentials");

  script_category(ACT_GATHER_INFO);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("hp_power_manager_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hp_power_manager/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Change the password for the user 'admin'.");

  script_tag(name:"summary", value:"The installed remote HP Power Manager has the default credentials 'admin' for
  username and password set.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

variables = "HtmlOnly=true&Login=admin&Password=admin&loginButton=Submit%20Login";
host      = http_host_name( port:port );
filename  = dir + "/goform/formLogin";

req = string( "POST ", filename, " HTTP/1.0\r\n",
              "Referer: ","http://", host, filename, "\r\n",
              "Host: ", host, "\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Content-Length: ", strlen(variables),
              "\r\n\r\n",
              variables
            );
result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if ("top.location.href = '/Contents/index.asp';" >< result) {
  report = report_vuln_url(port:port, url:filename);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);