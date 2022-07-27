###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_telesquare_skt_lte_router_SDT-CS3B1_mult_vuln.nasl 12894 2018-12-28 13:27:22Z mmartin $
#
# Telesquare SKT LTE Router SDT-CS3B1 Multiple Vulnerabilities
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/h:telesquare:sdt-cs3b1";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812367");
  script_version("$Revision: 12894 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-28 14:27:22 +0100 (Fri, 28 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-12-28 11:04:35 +0530 (Thu, 28 Dec 2017)");
  script_name("Telesquare SKT LTE Router SDT-CS3B1 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is running Telesquare SKT LTE Router
  SDT-CS3B1 and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to read the sensitive information or not.");

  script_tag(name:"insight", value:"Multiple vulnerabilities exists as,

  - Application provides direct access to objects based on user-supplied input.

  - Application allows unauthenticated user to execute reboot command .

  - Application interface allows users to perform certain actions via HTTP
    requests without performing any validity checks to verify the requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to gain access to potentially sensitive information, bypass
  authorization and access resources and functionalities in the system and
  conduct a denial of service condition.");

  script_tag(name:"affected", value:"Telesquare SKT LTE Router SDT-CS3B1");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5445.php");
  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5444.php");
  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5443.php");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_telesquare_skt_lte_router_SDT-CS3B1_detect.nasl");
  script_mandatory_keys("telesquare/SDT-CS3B1/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.telesquare.co.kr");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!ltePort = get_app_port(cpe:CPE)){
  exit(0);
}

if(http_vuln_check(port:ltePort, url: "/cgi-bin/systemutil.cgi?Command=SystemInfo", pattern:"<Model>SDT-CS3B1<",
                   extra_check: make_list("<FwVer>SDT-CS3B1", "<LteVer>", "<CMState>", "<uicc_state>"),
                   check_header:TRUE))
{
  report = report_vuln_url(port:ltePort, url:"/cgi-bin/systemutil.cgi?Command=SystemInfo");
  security_message(port:ltePort, data:report);
  exit(0);
}
exit(0);
