###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe ColdFusion Multiple Path Disclosure Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902586");
  script_version("2019-05-17T12:32:34+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 12:32:34 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2011-11-17 10:10:10 +0530 (Thu, 17 Nov 2011)");
  script_name("Adobe ColdFusion Multiple Path Disclosure Vulnerabilities");
  script_xref(name:"URL", value:"http://websecurity.com.ua/5377/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Nov/250");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107017/adobecoldfusion-disclosedos.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("coldfusion/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"affected", value:"Adobe ColdFusion version 9 and prior.");

  script_tag(name:"insight", value:"The flaw is due to insufficient error checking, allows remote
  attackers to obtain sensitive information via a direct request to a
  .cfm file, which reveals the installation path in an error message.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Adobe ColdFusion and is prone to multiple
  path disclosure vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_kb_item(string("coldfusion/", port, "/installed")))
  exit(0);

url = "/CFIDE/adminapi/_datasource/formatjdbcurl.cfm";

if(http_vuln_check(port:port, url:url,
   pattern:".*\\wwwroot\\CFIDE\\adminapi\\_datasource\\formatjdbcurl.cfm",
   extra_check:"Unable to display error's location in a CFML template.")) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
}
