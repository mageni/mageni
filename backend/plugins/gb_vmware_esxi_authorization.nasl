# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105058");
  script_version("2021-09-16T12:48:59+0000");
  script_tag(name:"last_modification", value:"2021-09-17 10:28:54 +0000 (Fri, 17 Sep 2021)");
  script_tag(name:"creation_date", value:"2014-07-07 10:42:27 +0200 (Mon, 07 Jul 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ESXi Authorization"); # nb: Don't change the script name, this name is hardcoded within some manager functions...
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Credentials");

  script_add_preference(name:"ESXi login name:", type:"entry", value:"", id:1); # nb: Don't change this name and id, these are hardcoded / used in GVMd
  script_add_preference(name:"ESXi login password:", type:"password", value:"", id:2); # nb: Don't change this name and id, these are hardcoded / used in GVMd

  script_tag(name:"summary", value:"This VT allows users to enter the information required to
  authorize and login into the ESXi SOAP API via HTTP.

  This information is used by tests that require authentication.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

esxi_login    = script_get_preference( "ESXi login name:", id:1 );
esxi_password = script_get_preference( "ESXi login password:", id:2 );

if( esxi_login )    set_kb_item( name:"esxi/login_filled/0", value:esxi_login );
if( esxi_password ) set_kb_item( name:"esxi/password_filled/0", value:esxi_password );

exit( 0 );