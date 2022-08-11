###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_starttls_smtp_not_supported.nasl 13153 2019-01-18 14:31:32Z cfischer $
#
# SMTP Missing Support For STARTTLS
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105091");
  script_version("$Revision: 13153 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 15:31:32 +0100 (Fri, 18 Jan 2019) $");
  script_tag(name:"creation_date", value:"2014-09-23 14:29:22 +0100 (Tue, 23 Sep 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SMTP Missing Support For STARTTLS");
  script_category(ACT_GATHER_INFO);
  script_family("SMTP problems");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_starttls_smtp.nasl");
  script_mandatory_keys("smtp/starttls/not_supported");

  script_tag(name:"summary", value:"The remote SMTP server does not support the 'STARTTLS' command.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item( "smtp/starttls/not_supported/port" );
if( ! port )
  exit( 0 );

log_message( port:port, data:"The remote SMTP server does not support the 'STARTTLS' command." );
exit( 0 );