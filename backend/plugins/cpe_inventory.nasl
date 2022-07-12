###############################################################################
# OpenVAS Vulnerability Test
# $Id: cpe_inventory.nasl 14324 2019-03-19 13:31:53Z cfischer $
#
# CPE Inventory
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810002");
  script_version("$Revision: 14324 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:31:53 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-11-18 11:43:05 +0100 (Wed, 18 Nov 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("CPE Inventory");
  script_category(ACT_END);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("Service detection");

  script_xref(name:"URL", value:"http://cpe.mitre.org/");

  script_tag(name:"summary", value:"This routine uses information collected by other routines about
  CPE identities of operating systems, services and
  applications detected during the scan.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

ip = get_host_ip();

report = ''; # nb: To make openvas-nasl-lint happy...
cpes = host_details_cpes();

# Sort to not report changes on delta reports if just the order is different
cpes = sort( cpes );

# update the report with CPE's registered as host details
foreach cpe( cpes ) {
  if( cpe >!< report ) {
    report += ip + '|' + cpe + '\n';
  }
}

if( report != '' ) {
  set_kb_item( name:"cpe_inventory/available", value:TRUE );
  log_message( proto:"CPE-T", data:report );
}

exit( 0 );