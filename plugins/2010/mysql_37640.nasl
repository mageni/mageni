###############################################################################
# OpenVAS Vulnerability Test
# $Id: mysql_37640.nasl 11830 2018-10-11 06:12:56Z cfischer $
#
# MySQL 5.0.51a Unspecified Remote Code Execution Vulnerability
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

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100436");
  script_version("$Revision: 11830 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 08:12:56 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2010-01-11 11:18:50 +0100 (Mon, 11 Jan 2010)");
  script_cve_id("CVE-2009-4484");
  script_bugtraq_id(37640);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MySQL 5.0.51a Unspecified Remote Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37640");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/dailydave/2010-q1/0002.html");
  script_xref(name:"URL", value:"http://www.mysql.com/");
  script_xref(name:"URL", value:"http://intevydis.com/mysql_demo.html");

  script_tag(name:"summary", value:"MySQL 5.0.51a is prone to an unspecified remote code-execution
  vulnerability.");

  script_tag(name:"insight", value:"Very few technical details are currently available.");

  script_tag(name:"impact", value:"An attacker can leverage this issue to execute arbitrary code within
  the context of the vulnerable application. Failed exploit attempts
  will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"This issue affects MySQL 5.0.51a. Other versions may also be
  vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!ver = get_app_version(cpe:CPE, port:port)) exit(0);

if(ver =~ "^5.0.51a") {
  report = report_fixed_ver(installed_version:ver, fixed_version:"Unknown");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);