###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arecont_vision_nvr_no_admin.nasl 12881 2018-12-25 16:53:59Z tpassfeld $
#
# Arecont Vision NVR No Administrator Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.114052");
  script_version("$Revision: 12881 $");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-25 17:53:59 +0100 (Tue, 25 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-25 17:01:04 +0100 (Tue, 25 Dec 2018)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Arecont Vision NVR No Administrator Vulnerability");
  script_dependencies("gb_arecont_vision_nvr_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("arecont_vision/nvr/detected");

  script_xref(name:"URL", value:"https://faq.arecontvision.com/questions/16/What+is+the+default+username+and+password+for+my+camera%3F");

  script_tag(name:"summary", value:"The script checks if the installation of Arecont Vision's NVR software has no administrator user set
  at the remote web server.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The configuration of Arecont Vision's NVR software incomplete or misconfigured.
  Arecont Vision cameras do not ship with authentication enabled. It is up to the user to enable authentication,
  which means that initially, everyone can have access to the live camera feed and all configurations,
  including setting up an administrator user themselves.");

  script_tag(name:"vuldetect", value:"Checks if authentication is requested by the server to access information about the presence of an admin user.");

  script_tag(name:"solution", value:"Create an administrator user as soon as possible, to avoid exposing your live camera feed and configuration.
  Always choose a secure password and never choose common guessable default credentials such as 'admin:admin'.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");


CPE = "cpe:/h:arecont_vision:nvr";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT in the GSA

url = "/cgi-bin/get.cgi?account.admin.&account.user";

req = http_get_req(port: port, url: url);

res = http_send_recv(port: port, data: req);

if('"account.admin.id":["ok","admin","",""]' >< res) {
  report = "Arecont Vision NVR is missing an administrator user!";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
