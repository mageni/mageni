###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_op5_monitor_59880.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# op5 Monitor Multiple Information Disclosure and Security Bypass Vulnerabilities
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
CPE = "cpe:/a:op5:monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103712");
  script_bugtraq_id(59880);
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_name("op5 Monitor Multiple Information Disclosure and Security Bypass Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59880");
  script_xref(name:"URL", value:"http://www.op5.com/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-05-16 11:45:26 +0200 (Thu, 16 May 2013)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_op5_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OP5/installed");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"op5 Monitor is prone to multiple information-disclosure and security-
bypass vulnerabilities.

An attacker may exploit these issues to obtain sensitive information
and bypass certain security restrictions.

op5 Monitor versions prior to 6.1.0 are vulnerable.");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(vers = get_app_version(cpe:CPE, port:port)) {

  if(version_is_less(version: vers, test_version: "6.1.0")) {
      security_message(port:port);
      exit(0);
  }

  exit(99);

}

exit(0);
