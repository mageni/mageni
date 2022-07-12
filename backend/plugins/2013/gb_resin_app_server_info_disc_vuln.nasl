##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_resin_app_server_info_disc_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# Resin Application Server Source Code Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803713");
  script_version("$Revision: 11401 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-06-10 16:11:12 +0530 (Mon, 10 Jun 2013)");
  script_name("Resin Application Server Source Code Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121933");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013060064");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/codes/resin_scd.txt");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5144.php");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Resin/banner");

  script_tag(name:"insight", value:"The flaw is due to an improper sensitization of the 'file'
  parameter when used for reading help files. An attacker can exploit this
  vulnerability by directly requesting a '.jsp' file.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Resin Application Server and prone to
  source code disclosure vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to view its
  source code that might reveal sensitive information.");
  script_tag(name:"affected", value:"Resin Application Server version 4.0.36");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("Server: Resin" >!< banner){
  exit(0);
}

url = '/resin-doc/viewfile/?file=index.jsp';

## Send the request and confirm the exploit
if(http_vuln_check(url:url, pattern:'resin-doc.*default-homepage', port:port,
  extra_check:make_list('getServerName', 'hasResinDoc', 'hasOrientation')))
{
  security_message(port:port);
  exit(0);
}

exit(99);
