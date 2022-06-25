###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_family_connections_40043.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Family Connections 2.2.3 Multiple SQL Injection Vulnerabilities
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

CPE = 'cpe:/a:haudenschilt:family_connections_cms';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100634");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-11 20:07:01 +0200 (Tue, 11 May 2010)");
  script_bugtraq_id(40043);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Family Connections 2.2.3 Multiple SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40043");
  script_xref(name:"URL", value:"http://www.familycms.com/index.php");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("family_connections_detect.nasl");
  script_mandatory_keys("family_connections/installed");

  script_tag(name:"summary", value:"Family Connections is prone to multiple SQL-injection vulnerabilities because
it fails to sufficiently sanitize user-supplied data before using it in an SQL query.

Exploiting these issues could allow an attacker to compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database.

Family Connections 2.2.3 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "2.0.0", test_version2: "2.2.3")) {
  security_message(port:port);
  exit(0);
}

exit(99);
