###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unprotected_lexmark_printers.nasl 7158 2017-09-18 06:38:57Z cfischer $
#
# Unprotected Lexmark Printer
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103686");
  script_version("$Revision: 7158 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 08:38:57 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2013-03-28 11:51:27 +0100 (Thu, 28 Mar 2013)");
  script_name("Unprotected Lexmark Printer");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_lexmark_printers_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("lexmark_printer/installed");

  script_xref(name:"URL", value:"http://www1.lexmark.com/en_US/");

  script_tag(name:"summary", value:"The remote Lexmark Printer is not protected by a password.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration without requiring authentication.");

  script_tag(name:"solution", value:"Set a password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("lexmark_printers.inc");
include("http_func.inc");

port = get_kb_item( "lexmark_printer/port" );
if( ! port ) exit( 0 );

model = get_kb_item( "lexmark_model" );
if( ! model ) exit( 0 );

ret = check_lexmark_default_login( model:model, port:port );
if( ret && ret == 2 ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
