###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_bbcode_xss_vuln.nasl 11553 2018-09-22 14:22:01Z cfischer $
#
# phpMyAdmin 'error.php' Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801660");
  script_version("$Revision: 11553 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 16:22:01 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-12-13 15:28:53 +0100 (Mon, 13 Dec 2010)");
  script_cve_id("CVE-2010-4480");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("phpMyAdmin 'error.php' Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15699/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3133");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject arbitrary
HTML code within the error page and conduct phishing attacks.");
  script_tag(name:"affected", value:"phpMyAdmin version 3.3.8.1 and prior.");
  script_tag(name:"insight", value:"The flaw is caused by input validation errors in the 'error.php'
script when processing crafted BBcode tags containing '@' characters, which
could allow attackers to inject arbitrary HTML code within the error page
and conduct phishing attacks.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running phpMyAdmin and is prone to Cross-Site
Scripting Vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

url = string(dir,"/error.php?type=OpenVAS+XSS+Test&error=Attack+via+",
                 "characters+injection+-+[a%40http://www.openvas.org%40_self]",
                 "This%20Is%20a%20Link[%2Fa]");

if(http_vuln_check(port:port, url:url, pattern:'<h1>phpMyAdmin - OpenVAS XSS Test</h1>',
                   extra_check: make_list('Attack via characters injection',
                   '<a href="http://www.openvas.org" target="_self">This Is a Link</a>')))
{
  security_message(port);
  exit(0);
}
