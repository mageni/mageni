###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_report_running_kernel.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Report running Kernel
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105885");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-05 13:45:04 +0200 (Mon, 05 Sep 2016)");
  script_name("Report running Kernel");

  script_tag(name:"summary", value:"This script reports the running kernel.");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_gather_linux_host_infos.nasl");
  script_mandatory_keys("Host/running_kernel_version");
  exit(0);
}

if( ! kv = get_kb_item( "Host/running_kernel_version" ) ) exit( 0 );

uname = get_kb_item( "Host/uname" );

report = 'The remote host is running Linux Kernel "' + kv + '".\n\n';
if( uname ) report += 'Concluded from uname: ' + uname + '\n';

log_message( port:0, data:report );
exit( 0 );


