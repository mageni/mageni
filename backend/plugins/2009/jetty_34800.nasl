###############################################################################
# OpenVAS Vulnerability Test
# $Id: jetty_34800.nasl 13685 2019-02-15 10:06:52Z cfischer $
#
# Jetty Cross Site Scripting and Information Disclosure
# Vulnerabilities
#
# Authors
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100183");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-05-04 20:25:02 +0200 (Mon, 04 May 2009)");
  script_cve_id("CVE-2009-1523");
  script_bugtraq_id(34800);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Jetty Cross Site Scripting and Information Disclosure Vulnerabilities");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Jetty/banner");

  script_tag(name:"solution", value:"The vendor has released an update.");

  script_tag(name:"summary", value:"Jetty is prone to a cross-site scripting vulnerability and an
  information-disclosure vulnerability.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site, steal cookie-based
  authentication credentials, and obtain sensitive information.");

  script_tag(name:"affected", value:"Jetty 6.1.16 and prior versions are affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34800");
  script_xref(name:"URL", value:"http://jetty.mortbay.org/jetty/index.html");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || !egrep(pattern:"Server: Jetty", string:banner) ) exit(0);

version = eregmatch(pattern: "Server: Jetty\(([0-9.]+[pre0-9]*)\)", string: banner);

if(!isnull(version[1])) {
  if(version_is_less_equal(version: version[1], test_version: "6.1.16")) {
   security_message(port:port);
   exit(0);
 }
}

exit(99);