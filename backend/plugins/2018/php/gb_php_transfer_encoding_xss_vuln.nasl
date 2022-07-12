###############################################################################
# OpenVAS Vulnerability Test
#
# PHP 'Transfer-Encoding: chunked' XSS Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH http://www.greenbone.net
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814021");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2018-17082");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-09-18 12:42:13 +0530 (Tue, 18 Sep 2018)");
  script_name("PHP 'Transfer-Encoding: chunked' XSS Vulnerability");

  script_tag(name:"summary", value:"The host is running php and is prone to
  cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and confirm
  the vulnerability from response.");

  script_tag(name:"insight", value:"The flaw is due to the bucket brigade is
  mishandled in the php_handler function in 'sapi/apache2handler/sapi_apache2.c'
  script.");

  script_tag(name:"impact", value:"Successful exploitation allow remote
  attacker to execute arbitrary script code in the browser of an unsuspecting
  user in the context of the affected site. This may allow the attacker to
  steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Apache2 component in PHP before 5.6.38, 7.0.x
  before 7.0.32, 7.1.x before 7.1.22, and 7.2.x before 7.2.10.");

  script_tag(name:"solution", value:"Upgrade to PHP 5.6.38 or 7.2.10 or 7.1.22
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");
  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=76582");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "secpod_apache_detect.nasl");
  script_mandatory_keys("php/installed", "apache/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");

if(!phport = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:phport)) exit(0);

req = http_post_req(port:phport,
                    url:"/index.php",
                    data:'<script>alert(document.cookie)</script>',
                    add_headers: make_array("Transfer-Encoding", "chunked"));
res = http_send_recv(port:phport, data:req);

if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res &&
   res =~ "Server: Apache.*PHP")
{
  report = report_vuln_url(port:phport, url:"/index.php");
  security_message(port:phport, data:report);
  exit(0);
}
exit(0);
