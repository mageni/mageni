###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smc8024l2_54390.nasl 11266 2018-09-06 10:59:26Z cfischer $
#
# SMC Networks SMC8024L2 Switch Web Interface Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103513");
  script_bugtraq_id(54390);
  script_cve_id("CVE-2012-2974");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11266 $");

  script_name("SMC Networks SMC8024L2 Switch Web Interface Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54390");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/377915");

  script_tag(name:"last_modification", value:"$Date: 2018-09-06 12:59:26 +0200 (Thu, 06 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-07-12 10:05:05 +0200 (Thu, 12 Jul 2012)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The SMC Networks SMC8024L2 switch is prone to a remote authentication-
  bypass vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to gain unauthorized administrative
  access to all configuration pages to affected devices.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
url = "/index.html";

buf = http_get_cache(port:port, item:url);

if("<title>SMC Networks Web Interface" >< buf) {

  url = '/status/status_ov.html';
  if(http_vuln_check(port:port, url:url, pattern:"<title>Status Overview",extra_check:make_list("macAddress","opVersion","systemName"))) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
