###############################################################################
# OpenVAS Vulnerability Test
#
# TemaTres Multiple XSS and SQL Injection Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800801");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-05-19 08:03:45 +0200 (Tue, 19 May 2009)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1583", "CVE-2009-1584", "CVE-2009-1585");
  script_bugtraq_id(34830);
  script_name("TemaTres Multiple XSS and SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34983");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34990");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8615");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8616");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_tematres_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tematres/detected");

  script_tag(name:"impact", value:"Successful attacks will let the attacker steal cookie-based authentication
  credentials, compromise the application, access or modify data, or can exploit
  latest vulnerabilities in the underlying database when 'magic_quotes_gpc' is disabled.");

  script_tag(name:"affected", value:"TemaTres version 1.031 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - In-adequate check of user supplied input which causes input validation error
  in the search form.

  - Validation check error in accepting user input for the following parameters
  a) _expresion_de_busqueda, b) letra  c) estado_id and d) tema e) PATH_TO inside index.php.

  - Validation check error in accepting user input for the following parameters
  a) y b) ord and c) m inside sobre.php.

  - Validation check error in accepting user input for the following parameters
  a) mail b) password inside index.php.

  - Validation check error in accepting user input for the following parameters
  a) dcTema b) madsTema c) zthesTema d) skosTema and e) xtmTema inside xml.php.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to TemaTres version 1.033 or later.");

  script_tag(name:"summary", value:"The host is running TemaTres and is prone to Multiple XSS and SQL
  Injection Vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

tematresPort = get_http_port(default:80);

tematresVer = get_kb_item("www/" + tematresPort + "/TemaTres");
tematresVer = eregmatch(pattern:"^(.+) under (/.*)$", string:tematresVer);
if(tematresVer[1] != NULL)
{
  if(version_is_less_equal(version:tematresVer[1], test_version:"1.031")){
    security_message(tematresPort);
  }
}
