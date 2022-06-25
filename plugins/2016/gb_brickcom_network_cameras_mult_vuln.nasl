###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_brickcom_network_cameras_mult_vuln.nasl 11607 2018-09-25 13:53:15Z asteins $
#
# Brickcom Network Cameras Multiple Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.808159");
  script_version("$Revision: 11607 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 15:53:15 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-06-10 17:32:08 +0530 (Fri, 10 Jun 2016)");
  script_name("Brickcom Network Cameras Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_brickcom_network_camera_detect.nasl");
  script_mandatory_keys("brickcom/network_camera/detected");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136693/OLSA-2015-12-12.txt");

  script_tag(name:"summary", value:"The host is running a Brickcom Network Camera
  device and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks
  whether it is able to login or not.");

  script_tag(name:"insight", value:"The flaws exist due to:

  - 'syslog.dump', 'configfile.dump' files are accessible without
    authenication.

  - Credentials and other sensitive information are stored in plain text.

  - The usage of defaults Credentials like 'admin:admin', 'viewer:viewer',
    'rviewer:rviewer'.

  - An improper input validation for parameter 'action' to
    'NotificationTest.cgi' script.

  - A Cross-site Request Forgery.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  access sensitive information stored in html page, gain administrative access,
  execute cross-site scripting and cross-site request forgery attacks.");

  script_tag(name:"affected", value:"For information on affected products and
  firmware versions, please refer to the link mentioned in reference.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");

if(model = get_kb_item("brickcom/network_camera/model")) {
  CPE = "cpe:/h:brickcom:" + tolower(model);
} else {
  CPE = "cpe:/h:brickcom:network_camera";
}

if(!bric_port = get_app_port(cpe:CPE)) exit(0);

host = http_host_name(port:bric_port);

url = "/user_management_config.html";
userpasswds = make_list("admin:admin", "viewer:viewer", "rviewer:rviewer");

foreach userpass(userpasswds){
  userpass64 = base64(str: userpass);

  req =  'GET ' + url + ' HTTP/1.1\r\n' +
         'Host: ' + host + '\r\n' +
         'Authorization: Basic ' + userpass64 + '\r\n' +
         '\r\n';
  res =  http_send_recv(port:bric_port, data:req);

  if('HTTP/1.1 200 Ok' >< res && 'Brickcom Corporation' >< res &&
     ('<title>User Management</title>' >< res || 'Camera Configuration Utility' >< res || '<title>Live View</title>')
     && (('="viewer"' >< res && '="admin"' >< res && '="rviewer"' >< res) || "viewer=='admin'" >< res)) {
      report = 'Authentication bypass possible using the login and password: ' + userpass + '\r\n\r\n';
      report += report_vuln_url(port:bric_port, url:url);
      security_message(port:bric_port, data:report);
      exit(0);
  }
}

exit(99);
