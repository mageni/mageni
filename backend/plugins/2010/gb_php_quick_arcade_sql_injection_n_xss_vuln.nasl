##############################################################################
# OpenVAS Vulnerability Test
#
# PHP Quick Arcade SQL Injection and Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
################################i###############################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801364");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-06-21 15:32:44 +0200 (Mon, 21 Jun 2010)");
  script_cve_id("CVE-2010-1661", "CVE-2010-1662");
  script_bugtraq_id(39733);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP Quick Arcade SQL Injection and Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12416/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1013");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1004-exploits/phpquickarcade-sqlxss.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_quick_arcade_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php-quick-arcade/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to steal cookie-based
  authentication credentials, compromise the application, access or modify data.");

  script_tag(name:"affected", value:"PHP-Quick-Arcade version 3.0.21 and prior.");

  script_tag(name:"insight", value:"The flaws are due to,

  - Input validation errors in the 'Arcade.php' and 'acpmoderate.php' scripts
  when processing the 'phpqa_user_c' cookie or the 'id' parameter, which could
  be exploited by malicious people to conduct SQL injection attacks.

  - Input validation error in the 'acpmoderate.php' script when processing the
  'serv' parameter, which could allow cross site scripting attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running PHP Quick Arcade and is prone to SQL
  injection and cross site scripting Vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

phpqaPort = get_http_port(default:80);

phpqaVer = get_kb_item("www/" + phpqaPort + "/PHP-Quick-Arcade");
if(!phpqaVer)
  exit(0);

phpqaVer = eregmatch(pattern:"^(.+) under (/.*)$", string:phpqaVer);
if(isnull(phpqaVer[1]))
  exit(0);

if(version_is_less_equal(version:phpqaVer[1], test_version:"3.0.21")){
  security_message(phpqaPort);
}
