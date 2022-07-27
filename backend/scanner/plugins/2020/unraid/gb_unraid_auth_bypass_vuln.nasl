# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/o:unraid:unraid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143518");
  script_version("2020-02-14T08:35:48+0000");
  script_tag(name:"last_modification", value:"2020-02-14 09:43:33 +0000 (Fri, 14 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-14 07:25:48 +0000 (Fri, 14 Feb 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2020-5849");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unraid OS 6.8.0 Authentication Bypass Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_unraid_http_detect.nasl");
  script_mandatory_keys("unraid/detected");
  script_require_ports("Services/www", 80, 443);

  script_tag(name:"summary", value:"The Web UI of Unraid OS is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"In order to check if a web page requires authentication, unraid uses a
  auth_request.php file that contains a whitelist which uses the strpos function for comparing strings. The
  whitelist can therefore be bypassed by appending additional characters to an entry in the whitelist.");

  script_tag(name:"impact", value:"An unauthenticated attacker might get full control over the host.");

  script_tag(name:"affected", value:"Unraid OS version 6.8.0.");

  script_tag(name:"solution", value:"Update to version 6.8.1 or later.");

  script_xref(name:"URL", value:"https://sysdream.com/news/lab/2020-02-06-cve-2020-5847-cve-2020-5849-unraid-6-8-0-unauthenticated-remote-code-execution-as-root/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

# Already no authentication in place
if (get_kb_item("unraid/http/" + port + "/noauth"))
  exit(0);

url = dir + "/webGui/images/green-on.png/Settings";

if (http_vuln_check(port: port, url: url, pattern: '"PanelText">Date and Time',
                    extra_check: '"PanelText">Disk Settings', check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
