###############################################################################
# OpenVAS Vulnerability Test
# $Id: system_characteristics.nasl 8346 2018-01-09 14:56:22Z cfischer $
#
# Show System Characteristics
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103999");
  script_version("$Revision: 8346 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 15:56:22 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2011-03-08 16:17:59 +0100 (Tue, 08 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Show System Characteristics");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("kb_2_sc.nasl", "gb_nist_win_oval_sys_char_generator.nasl");
  script_mandatory_keys("system_characteristics/created");

  script_xref(name:"URL", value:"https://www.mageni.net/docs");

  script_tag(name:"summary", value:"Show OVAL System Characteristics if they have been previously gathered and are available
  in the Knowledge Base.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

if( get_kb_item( "SMB/WindowsVersion" ) ) {
  sc = get_kb_item( "nist_windows_system_characteristics" );
} else {
  sc = get_kb_item( "system_characteristics" );
}

if( sc ) {
  log_message( port:0, data:sc, proto:"OVAL-SC" );
}

exit( 0 );
