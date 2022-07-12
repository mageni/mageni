###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iball_baton_150m_wireless_router_auth_bypass_vuln.nasl 12043 2018-10-23 14:16:52Z mmartin $
#
# iBall Baton 150M Wireless Router Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/h:iball:baton_150m_wireless-n_router";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811313");
  script_version("$Revision: 12043 $");
  script_cve_id("CVE-2017-6558", "CVE-2017-14244");
  script_bugtraq_id(96822);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 16:16:52 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-31 12:06:39 +0530 (Thu, 31 Aug 2017)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("iBall Baton 150M Wireless Router Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"The host is running iBall Baton 150M
  Wireless Router and is prone to authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to get specific information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - iball Baton 150M Router login page is insecurely developed and any attacker
    could bypass the admin authentication just by tweaking the password.cgi file.

  - iBall ADSL2+ Home Router does not properly authenticate when pages are
    accessed through cgi version.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to bypass authentication mechanism and perform
  unauthorized actions and can access sensitive information and perform actions
  such as reset router, downloading backup configuration, upload backup etc.
  This may lead to further attacks.");

  script_tag(name:"affected", value:"iBall Baton 150M Wireless-N ADSI.2+ Router 1.2.6 build 110401.
  iBall ADSL2+ Home Router WRA150N Firmware version FW_iB-LR7011A_1.0.2");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42591");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42740");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Mar/22");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_iball_baton_150m_wireless_router_detect.nasl");
  script_mandatory_keys("iBall_Baton_150M_Router/detected");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!netPort = get_app_port(cpe:CPE))
  exit(0);

url = "/password.cgi";

req = http_get(item: url, port:netPort);
rcvRes = http_keepalive_send_recv(port:netPort, data:req);

if(rcvRes =~ "HTTP/1.. 200" && ">Access Control -- Password<" >< rcvRes &&
   "Access to your DSL router" >< rcvRes && "pwdAdmin =" >< rcvRes &&
   "pwdSupport =" >< rcvRes && "pwdUser =" >< rcvRes)
{
  report = report_vuln_url(port:netPort, url:url);
  security_message( port:netPort, data:report);
  exit(0);
}

exit(99);
