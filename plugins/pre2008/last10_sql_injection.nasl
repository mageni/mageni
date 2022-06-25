# OpenVAS Vulnerability Test
# $Id: last10_sql_injection.nasl 13975 2019-03-04 09:32:08Z cfischer $
# Description: vBulletin last10.php SQL Injection
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
#

CPE = 'cpe:/a:vbulletin:vbulletin';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16043");
  script_version("$Revision: 13975 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(11825);
  script_name("vBulletin last10.php SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_mandatory_keys("vBulletin/installed");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software or disable it");
  script_tag(name:"summary", value:"The remote host is running last10.php, an unofficial plugin
 for vBulletin which allows users to add a revolving ticker
 showing the last10 topics of his/her forum.

 This set of script may allow an attacker to cause an SQL
 Injection vulnerability allowing an attacker to cause the
 program to execute arbitrary SQL statements.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

req = http_get(item:string(dir, "/last10.php?ftitle='"), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly: TRUE);
if( res == NULL )exit(0);

if(("You have an error in your SQL syntax" >< res) ||
  ("WHERE thread.lastposter=" >< res)) {
    security_message(port:port);
    exit(0);
}

exit(99);