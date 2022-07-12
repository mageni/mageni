###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icewarp_mail_server_55507.nasl 11355 2018-09-12 10:32:04Z asteins $
#
# IceWarp Mail Server 'raw.php' Information Disclosure Vulnerability
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

CPE = "cpe:/a:icewarp:mail_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103565");
  script_bugtraq_id(55507);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11355 $");

  script_name("IceWarp Mail Server 'raw.php' Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55507");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/50441");

  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:32:04 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-09-13 10:46:19 +0200 (Thu, 13 Sep 2012)");

  script_category(ACT_ATTACK);

  script_tag(name:"qod_type", value:"remote_vul");

  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_icewarp_web_detect.nasl");
  script_mandatory_keys("icewarp/installed");

  script_tag(name:"summary", value:"IceWarp Mail Server is prone to an information-disclosure vulnerability.");

  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to obtain sensitive information that may aid in further attacks.");

  script_tag(name:"affected", value:"IceWarp Mail Server 10.4.3 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of
this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

url = dir + '/pda/controller/raw.php';

if (http_vuln_check(port: port, url: url, pattern: "<title>phpinfo\(\)", check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port:port, data: report);
  exit(0);
}

exit(0);
