###############################################################################
# OpenVAS Vulnerability Test
#
# MySQL Authentication bypass through a zero-length password
#
# Authors:
# Eli Kara <elik@beyondsecurity.com>
#
# Copyright:
# Copyright (C) 2004 Beyond Security
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12639");
  script_version("2019-04-24T07:26:10+0000");
  script_bugtraq_id(10654, 10655);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("MySQL Authentication bypass through a zero-length password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Beyond Security");
  script_family("Default Accounts");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL_MariaDB/installed");

  script_tag(name:"summary", value:"It is possible to bypass password authentication for a database
  user using a crafted authentication packet with a zero-length password

  Note: In order to use this script, the MySQL daemon has to allow connection from the
  scanning IP address");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);