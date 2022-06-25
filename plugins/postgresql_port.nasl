# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.116184");
  script_version("2021-05-21T10:21:47+0000");
  script_tag(name:"last_modification", value:"2021-05-25 10:22:08 +0000 (Tue, 25 May 2021)");
  script_tag(name:"creation_date", value:"2021-04-08 08:00:00 +0000 (Thu, 08 Apr 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("PostgreSQL: Port");

  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Compliance");
  script_dependencies("compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Port", type:"entry", value:"5432", id:1);
  script_add_preference(name:"Version", type:"entry", value:"", id:2);

  script_tag(name:"summary", value:"Enter the port used for PostgreSQL. If applicable, also enter the
  version number (12/11/10/9.6)");

  exit(0);
}

port = script_get_preference( "Port", id:1 );
if ( port != "" )
  set_kb_item( name:"Policy/PostgreSQL/port", value:port );
else
  set_kb_item( name:"Policy/PostgreSQL/port", value:"5432" );

version = script_get_preference( "Version", id:2 );
if ( version != "" )
  set_kb_item( name:"Policy/PostgreSQL/version", value:version );

exit(0);