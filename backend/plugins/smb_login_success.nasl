###############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_login_success.nasl 13248 2019-01-23 15:35:02Z cfischer $
#
# SMB Login Successful For Authenticated Checks
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.108539");
  script_version("$Revision: 13248 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 16:35:02 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-23 15:50:49 +0100 (Wed, 23 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SMB Login Successful For Authenticated Checks");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_login.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("login/SMB/success");

  script_tag(name:"summary", value:"It was possible to login using the provided SMB
  credentials. Hence authenticated checks are enabled.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smb_nt.inc");

port = get_kb_item( "login/SMB/success/port" );
if( ! port )
  port = kb_smb_transport();

log_message( port:port );
exit( 0 );