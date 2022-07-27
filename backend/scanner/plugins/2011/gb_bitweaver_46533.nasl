###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bitweaver_46533.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# Bitweaver 'edit.php' HTML Injection Vulnerability
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
CPE = "cpe:/a:bitweaver:bitweaver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103092");
  script_version("$Revision: 12018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-25 13:54:37 +0100 (Fri, 25 Feb 2011)");
  script_bugtraq_id(46533);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Bitweaver 'edit.php' HTML Injection Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46533");
  script_xref(name:"URL", value:"http://bitweaver.org");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_bitweaver_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Bitweaver/installed");
  script_tag(name:"summary", value:"Bitweaver is prone to an HTML-injection vulnerability because it fails
to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials, control how the site is rendered to the user, or launch
other attacks.

Bitweaver 2.8.1 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution", value:"Upgrade to the latest version.");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(vers = get_app_version(cpe:CPE, port:port)) {

  if(version_is_equal(version: vers, test_version: "2.8.1")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
