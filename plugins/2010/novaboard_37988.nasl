###############################################################################
# OpenVAS Vulnerability Test
# $Id: novaboard_37988.nasl 13865 2019-02-26 07:43:10Z ckuersteiner $
#
# NovaBoard 'forums' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer
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

CPE = "cpe:/a:novaboard:novaboard";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100478");
  script_version("$Revision: 13865 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 08:43:10 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-01-29 17:41:41 +0100 (Fri, 29 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0608");
  script_bugtraq_id(37988);

  script_name("NovaBoard 'forums' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37988");
  script_xref(name:"URL", value:"http://www.novaboard.net/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("novaboard_detect.nasl");
  script_mandatory_keys("novaboard/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"NovaBoard is prone to an SQL-injection vulnerability because it
fails to sufficiently sanitize user-supplied data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database.

NovaBoard 1.1.2 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
