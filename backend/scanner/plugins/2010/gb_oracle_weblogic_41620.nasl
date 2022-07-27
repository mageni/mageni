###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_weblogic_41620.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Oracle WebLogic Server Encoded URL Remote Vulnerability
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

CPE = "cpe:/a:bea:weblogic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100714");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-14 13:50:55 +0200 (Wed, 14 Jul 2010)");
  script_bugtraq_id(41620);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2010-2375");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle WebLogic Server Encoded URL Remote Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/41620");
  script_xref(name:"URL", value:"http://www.vsecurity.com/resources/advisory/20100713-1/");
  script_xref(name:"URL", value:"http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpujul2010.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("oracle_webLogic_server_detect.nasl");
  script_mandatory_keys("OracleWebLogicServer/installed");
  script_require_ports("Services/www", 7001);

  script_tag(name:"solution", value:"Vendor updates are available. Please contact the vendor for more
information.");

  script_tag(name:"summary", value:"Oracle WebLogic Server is prone to a remote vulnerability.

The vulnerability can be exploited over the 'HTTP' protocol. For an exploit to succeed, the attacker must have
'Plugins for Apache, Sun and IIS web servers' privileges.

This vulnerability affects the following supported versions:

7. SP7, 8.1 SP6, 9.0, 9.1, 9.2 MP3, 10.0 MP2, 10.3.2, 10.3.3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "10.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See reference");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
