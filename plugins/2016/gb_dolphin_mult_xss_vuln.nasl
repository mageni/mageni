###############################################################################
# OpenVAS Vulnerability Test
#
# Dolphin Multiple Cross Site Scripting Vulnerabilities
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

CPE = "cpe:/a:boonex:dolphin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808218");
  script_version("2019-05-10T14:24:23+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2016-06-06 09:51:58 +0530 (Mon, 06 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Dolphin Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Dolphin and is prone to
  multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"The multiple flaws are due to :

  - An insufficient validation of user supplied input via GET parameter
    'explain' to explanation.php script.

  - An insufficient validation of user supplied input via GET parameters
    'photos_only', 'online_only', 'mode' to viewFriends.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script into user's browser session.");

  script_tag(name:"affected", value:"Dolphin versions 7.0.7 and lower.");

  script_tag(name:"solution", value:"Upgrade to version 7.0.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Feb/326");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolphin_detect.nasl");
  script_mandatory_keys("Dolphin/Installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)) {
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

if(dir == "/") dir = "";

url =  dir + "/viewFriends.php?iUser=1&page=1&per_page=32&sort=activity&online_only='"+
             "><script>alert(document.cookie)</script>";

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\)</script>",
                   extra_check:make_list("Dolphin", "from BoonEx")))
{
  report = report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}
