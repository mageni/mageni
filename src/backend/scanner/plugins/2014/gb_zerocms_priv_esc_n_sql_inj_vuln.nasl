###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zerocms_priv_esc_n_sql_inj_vuln.nasl 11449 2018-09-18 10:04:42Z mmartin $
#
# ZeroCMS Privilege Escalation & SQL Injection Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804640");
  script_version("$Revision: 11449 $");
  script_cve_id("CVE-2014-4034", "CVE-2014-4195", "CVE-2014-4194", "CVE-2014-4710");
  script_bugtraq_id(67953, 68246, 68134, 68935);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 12:04:42 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-06-16 13:03:02 +0530 (Mon, 16 Jun 2014)");
  script_name("ZeroCMS Privilege Escalation & SQL Injection Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with ZeroCMS and
  is prone to privilege escalation, cross-site scripting and sql injection
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET
  request and check whether it is able execute sql query or not.");

  script_tag(name:"insight", value:"Input passed via the 'article_id' GET
  parameter to zero_view_article.php script, 'access_level' POST parameter to
  zero_transact_user.php script, 'Full Name' field to zero_user_account.php
  script and 'article_id' POST parameter to the zero_transact_article.php
  script is not properly sanitised before being used.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to gain unauthorized privileges and manipulate SQL queries in the
  backend database allowing for the manipulation or disclosure of arbitrary
  data, execute arbitrary HTML and script code in a user's browser session in
  the context of an affected site.");

  script_tag(name:"affected", value:"ZeroCMS version 1.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33743");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33702");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127005");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127164");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127262");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2014-5186.php");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/cms", "/zerocms", "/ZeroCMS", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if (">ZeroCMS<" >< rcvRes && ">Login<" >< rcvRes)
  {
    url = dir + "/zero_view_article.php?article_id=1337+union+select+concat" +
           "(0x53514c2d496e6a656374696f6e2d54657374),1,1,1,1,1" ;

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"SQL-Injection-Test<",
       extra_check: make_list(">Login<", ">ZeroCMS<")))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
