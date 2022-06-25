###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_op5_55191.nasl 11855 2018-10-12 07:34:51Z cfischer $
#
# op5 Monitor HTML Injection and SQL Injection Vulnerabilities
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
CPE = "cpe:/a:op5:monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103556");
  script_bugtraq_id(55191);
  script_version("$Revision: 11855 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:N");

  script_name("op5 Monitor HTML Injection and SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55191");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-30 10:46:24 +0200 (Thu, 30 Aug 2012)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_op5_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OP5/installed");
  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
information.");
  script_tag(name:"summary", value:"op5 Monitor is prone to an HTML-injection vulnerability and an
SQL-injection vulnerability because it fails to sanitize user-
supplied input.");

  script_tag(name:"impact", value:"Exploiting these issues may allow an attacker to compromise the
application, access or modify data, exploit vulnerabilities in the
underlying database, execute HTML and script code in the context of
the affected site, steal cookie-based authentication credentials,
or control how the site is rendered to the user, other attacks are
also possible.");

  script_tag(name:"affected", value:"op5 Monitor 5.4.2 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!vers = get_app_version(cpe:CPE, port:port))exit(0);

if(version_is_equal(version:vers, test_version: "5.4.2")) {

  security_message(port:port);
  exit(0);
}

exit(0);



