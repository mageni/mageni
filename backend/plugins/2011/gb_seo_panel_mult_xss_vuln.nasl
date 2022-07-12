##############################################################################
# OpenVAS Vulnerability Test
#
# Seo Panel Multiple Cross-site Scripting (XSS) Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801775");
  script_version("2019-05-16T08:02:32+0000");
  script_tag(name:"last_modification", value:"2019-05-16 08:02:32 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2011-04-26 15:24:49 +0200 (Tue, 26 Apr 2011)");
  script_cve_id("CVE-2010-4331");
  script_bugtraq_id(45828);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Seo Panel Multiple Cross-site Scripting (XSS) Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64725");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16000/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/515768/100/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
  input by the 'index.ctrl.php' or 'controllers/settings.ctrl.php' scripts. A
  remote attacker could exploit this vulnerability using the default_news or
  sponsors parameter to inject malicious script content into a web page.");

  script_tag(name:"solution", value:"Upgrade to version 2.2.0 or later.");

  script_tag(name:"summary", value:"This host is running Seo Panel and is prone to multiple Cross-
  site scripting vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of an
  affected site and potentially allowing the attacker to steal cookie-based
  authentication credentials or to control how the site is rendered to the user.");

  script_tag(name:"affected", value:"Seo Panel version 2.2.0.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) {
  exit(0);
}

host = http_host_name(port:port);

foreach dir (make_list_unique("/seopanel", "/SeoPanel", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/", port:port);

  if('<title>Seo Panel' >< rcvRes)
  {
    sndReq = string("GET ", dir, "/index.php?sec=news"," HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Cookie: default_news=<script>alert('XSS-TEST')</script>", "\r\n\r\n");
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    if(rcvRes =~ "HTTP/1\.. 200" && "<script>alert('XSS-TEST')</script>" >< rcvRes){
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
