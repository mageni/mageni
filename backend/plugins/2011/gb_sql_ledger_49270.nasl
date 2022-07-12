###############################################################################
# OpenVAS Vulnerability Test
#
# SQL-Ledger SQL Injection Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103226");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-08-25 15:23:29 +0200 (Thu, 25 Aug 2011)");
  script_bugtraq_id(49270);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("SQL-Ledger SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49270");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/ledger-smb/files/Development%20Snapshots/1.2.25-rc1/");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/ledger-smb/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/519383");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_sql_ledger_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sql-ledger/detected");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"LedgerSMB and SQL-Ledger are prone to an SQL-injection vulnerability
  because the application fails to properly sanitize user-supplied input before using it in an SQL query.");

  script_tag(name:"impact", value:"A successful exploit may allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(vers = get_version_from_kb(port:port, app:"SQL-Ledger")) {
  if(version_is_less(version: vers, test_version: "2.8.34")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
