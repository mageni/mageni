###############################################################################
# OpenVAS Vulnerability Test
# $Id: vBulletin_3_7_3_pl1_sql_injection.nasl 14335 2019-03-19 14:46:57Z asteins $
#
# vBulletin 'admincalendar.php' SQL Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100020");
  script_version("$Revision: 14335 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:46:57 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
  script_bugtraq_id(32348);
  script_cve_id("CVE-2008-6256");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("vBulletin 'admincalendar.php' SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vBulletin/installed");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to newest Version of VBulletin.");
  script_tag(name:"summary", value:"vBulletin is prone to an SQL-injection vulnerability because it
  fails to sufficiently sanitize user-supplied data before using it in
  an SQL query.

  Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.

  Note that to succeed, the attacker must have an administrative
  account with 'calendar' administrator access.

  vBulletin 3.7.3.pl1 is vulnerable, other versions may also be affected.");
  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

version = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(version)) exit(0);

matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$");

if (!isnull(matches)) {
 ver = matches[1];
 if ( ver <= "3.7.3.pl1" ) {
	security_message(port:port);
	exit(0);
 }
}

exit(0);
