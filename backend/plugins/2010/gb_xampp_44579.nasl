###############################################################################
# OpenVAS Vulnerability Test
#
# XAMPP Cross Site Scripting and Information Disclosure Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100885");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-11-02 13:46:58 +0100 (Tue, 02 Nov 2010)");
  script_bugtraq_id(44579);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("XAMPP Cross Site Scripting and Information Disclosure Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44579");
  script_xref(name:"URL", value:"http://www.apachefriends.org/en/xampp.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_xampp_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xampp/installed");

  script_tag(name:"summary", value:"XAMPP is prone to multiple cross-site scripting vulnerabilities and an
  information disclosure vulnerability because the application fails to
  sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to obtain sensitive information,
  steal cookie-based authentication information, and execute arbitrary
  client-side scripts in the context of the browser.");

  script_tag(name:"affected", value:"XAMPP 1.7.3 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!version = get_kb_item(string("www/", port, "/XAMPP")))
  exit(0);

url = string("/xampp/phonebook.php/%22%3E%3Cscript%3Ealert(%27vt-xss-test%27)%3C/script%3E");

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\('vt-xss-test'\)</script>", check_header:TRUE)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
