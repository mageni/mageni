# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108545");
  script_version("$Revision: 14046 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 08:54:49 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-07 14:16:55 +0100 (Thu, 07 Feb 2019)");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"cvss_base", value:"3.7");
  script_name("Report Vulnerabilities in inactive Linux Kernel(s)");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_END);
  script_family("General");
  script_dependencies("gather-package-list.nasl", "lsc_options.nasl");
  script_mandatory_keys("ssh/login/inactive_kernel_vulns/available");

  script_tag(name:"summary", value:"This script reports vulnerabilities found (via package manager
  based Local Security Checks) in installed but inactive Linux Kernel(s) with a lower severity.

  This functionality needs to be separately enabled with the setting 'Report vulnerabilities of inactive
  Linux Kernel(s) separately' of 'Options for Local Security Checks' (OID: 1.3.6.1.4.1.25623.1.0.100509).

  Please see the description of this VT for more background information on this functionality.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");

all_reports = get_kb_list( "ssh/login/inactive_kernel_vulns/reports/*" );
if( ! all_reports || ! is_array( all_reports ) )
  exit( 0 );

report_array = make_array();

# Sort to not report changes on delta reports if just the order is different
keys = sort( keys( all_reports ) );

uname = get_kb_item( "ssh/login/uname" );
if( uname )
  report = 'Current active/running Kernel (uname): ' + uname + '\n\n';

report += 'The vulnerabilities described in the VTs referenced by their OIDs are found within inactive Linux Kernel(s):\n\n';

foreach key( keys ) {

  split = split( key, sep:"/", keep:FALSE );
  if( max_index( split ) != 6 ) # nb: KB key is e.g. ssh/login/inactive_kernel_vulns/reports/1.3.6.1.4.1.25623.1.0.704078/linux-headers-4.9.0-3-common
    continue;

  oid = split[4];
  pkg = split[5];
  if( ! oid || ! pkg || "1.3.6.1.4.1.25623.1.0." >!< oid )
    continue;

  sub_report = get_kb_item( "ssh/login/inactive_kernel_vulns/reports/" + oid + "/" + pkg );
  if( ! sub_report )
    continue;

  if( report_array[oid] ) {
    __report = report_array[oid];
    report_array[oid] = __report + sub_report;
  } else {
    report_array[oid] = sub_report;
  }
}

foreach key( keys( report_array ) ) {
  report += 'OID: ' + key + '\n\n';
  report += report_array[key];
}

security_message( port:0, data:chomp( report ) );
exit( 0 );