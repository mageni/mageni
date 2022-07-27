###############################################################################
# OpenVAS Vulnerability Test
# $Id: mysql_single_row_subselect_dos.nasl 14010 2019-03-06 08:24:33Z cfischer $
#
# MySQL Single Row Subselect Remote DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2008 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80075");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2007-1420");
  script_bugtraq_id(22900);
  script_name("MySQL Single Row Subselect Remote DoS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2008 David Maciejak");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");

  script_tag(name:"summary", value:"The remote database server is prone to a denial of service attack.");

  script_tag(name:"insight", value:"According to its banner, the version of MySQL on the remote host is
  older than 5.0.37. Such versions are vulnerable to a remote denial of service when processing certain
  single row subselect queries.");

  script_tag(name:"impact", value:"A malicious user can crash the service via a specially-crafted SQL
  query.");

  script_tag(name:"solution", value:"Upgrade to MySQL version 5.0.37 or newer.");

  script_xref(name:"URL", value:"http://www.sec-consult.com/284.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/462339/100/0/threaded");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.0/en/releasenotes-cs-5-0-37.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if(ereg(pattern:"^5\.0\.([0-9]($|[^0-9])|[12][0-9]($|[^0-9])|3[0-6]($|[^0-9]))", string:ver)) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"5.0.37");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);