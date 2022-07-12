###############################################################################
# OpenVAS Vulnerability Test
#
# Mini Web Server Cross Site Scripting and Directory Traversal Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100614");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-04-30 13:41:49 +0200 (Fri, 30 Apr 2010)");
  script_bugtraq_id(39780);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Mini Web Server Cross Site Scripting and Directory Traversal Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39780");
  script_xref(name:"URL", value:"http://www.jibble.org/miniwebserver/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("JibbleWebServer/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Mini Web Server is prone to a directory-traversal vulnerability and a
  cross-site scripting vulnerability because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting these issues will allow an attacker to execute arbitrary
  script code in the browser of an unsuspecting user in the context of
  the affected site, and to view arbitrary local files and directories
  within the context of the webserver. This may let the attacker steal
  cookie-based authentication credentials and other harvested
  information may aid in launching further attacks.");

  script_tag(name:"affected", value:"Mini Web Server 1.0 is vulnerable, other versions may also be
  affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner || "Server: JibbleWebServer" >!< banner)
  exit(0);

version = eregmatch(pattern:"Server: JibbleWebServer/([0-9.]+)", string:banner);
if(isnull(version[1]))exit(0);

if(version_is_equal(version: version[1], test_version:"1.0")) {
  security_message(port:port);
  exit(0);
}

exit(0);