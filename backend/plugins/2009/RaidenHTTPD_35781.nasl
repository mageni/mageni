###############################################################################
# OpenVAS Vulnerability Test
#
# RaidenHTTPD Cross Site Scripting and Local File Include Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.100245");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
  script_bugtraq_id(35781);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("RaidenHTTPD Cross Site Scripting and Local File Include Vulnerabilities");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RaidenHTTPD/banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released an update to address these issues. Please see
  the references for more information.");

  script_tag(name:"summary", value:"RaidenHTTPD is prone to local file-include and cross-site scripting
  vulnerabilities because the application fails to properly sanitize user-
  supplied input. These issues affect the WebAdmin component.");

  script_tag(name:"impact", value:"An attacker may leverage the cross-site scripting issue to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site.
  This may allow the attacker to steal cookie-based authentication credentials and to launch other attacks.

  Exploiting the local file-include issue allows remote attackers to
  view and subsequently execute local files within the context of the webserver process.");

  script_tag(name:"affected", value:"RaidenHTTPD 2.0 build 26 and prior versions are affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35781");
  script_xref(name:"URL", value:"http://raidenhttpd.com/changelog.txt");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

version = get_http_banner(port: port);
if(!version)
  exit(0);

if(!matches = eregmatch(string:version, pattern:"Server: RaidenHTTPD/([0-9.]+)"))
  exit(0);

vers = matches[1];

if(!isnull(vers)) {
  if(version_is_less_equal(version: vers, test_version: "2.0.26")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
