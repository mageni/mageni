# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108537");
  script_version("2021-09-16T12:48:59+0000");
  script_tag(name:"last_modification", value:"2021-09-17 10:28:54 +0000 (Fri, 17 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-01-23 15:50:49 +0100 (Wed, 23 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VMware ESXi Login Failed For Authenticated Checks");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("VMware Local Security Checks");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("login/ESXi/failed");
  script_tag(name:"summary", value:"It was NOT possible to login into the ESXi SOAP API via HTTP
  using the provided VMware ESXi credentials. Hence authenticated checks are NOT enabled.");

  script_tag(name:"solution", value:"Recheck the VMware ESXi credentials and configuration for
  authenticated checks as well as the output of the VT 'VMware ESXi scan initialization'
  (OID: 1.3.6.1.4.1.25623.1.0.103447).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item( "login/ESXi/failed/port" );
if( ! port )
  port = 0;

log_message( port:port );
exit( 0 );