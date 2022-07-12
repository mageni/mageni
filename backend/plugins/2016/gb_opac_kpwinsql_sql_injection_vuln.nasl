###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opac_kpwinsql_sql_injection_vuln.nasl 11596 2018-09-25 09:49:46Z asteins $
#
# OPAC KpwinSQL SQL Injection Vulnerability
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

CPE = "cpe:/a:opac:kpwinsql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808099");
  script_version("$Revision: 11596 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 11:49:46 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-06-28 14:57:29 +0530 (Tue, 28 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("OPAC KpwinSQL SQL Injection Vulnerability");

  script_tag(name:"summary", value:"The host is installed with OPAC KpwinSQL
  and is prone to sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  validation of user supplied input via 'detail_num' parameter in 'zaznam.php'
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to steal cookie-based authentication credentials, compromise the
  application, access or modify data, or exploit latent vulnerabilities in the
  underlying database.");

  script_tag(name:"affected", value:"OPAC KpwinSQL version 1.0.289 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40013");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_opac_kpwinsql_detect.nasl");
  script_mandatory_keys("KpwinSQL/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!opacPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:opacPort)){
  exit(0);
}

if(dir == "/") dir = "";

url = dir + "/zaznam.php?detail_num='SQL-INJECTION-TEST";

if(http_vuln_check(port:opacPort, url:url, check_header:TRUE,
                   pattern:"Dynamic SQL Error",
                   extra_check:make_list("SQL-INJECTION-TEST", "KPWIN", "OPACSQL")))
{
  report = report_vuln_url(port:opacPort, url:url);
  security_message(port:opacPort, data:report);
  exit(0);
}
