###############################################################################
# OpenVAS Vulnerability Test
# $Id: scan_info.nasl 11665 2018-09-28 07:14:18Z cfischer $
#
# Information about the scan
#
# Authors:
# Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 Tenable Network Security
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

# TODO: This NVT is actually not relevant anymore because it is returning
# data that are available in the scanner client anyway. In the early days
# such meta information were sent via NVT results because there was lack of
# a management unit. Now there is OpenVAS Manager and Host Details.
# The NVT is now disabled by default. Eventually it needs to be decided
# whether to entirely remove it.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19506");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_version("$Revision: 11665 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 09:14:18 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Information about the scan");
  script_category(ACT_END);
  script_copyright("Copyright (C) 2004 Tenable Network Security");
  script_family("General");

  script_add_preference(name:"Be silent", type:"checkbox", value:"yes");

  script_tag(name:"summary", value:"This script displays, for each tested host, information about the scan itself:

  - The version of the NVT feed

  - The type of NVT feed (Direct, Registered or GPL)

  - The version of the Scanner Engine

  - The port scanner(s) used

  - The port range scanned

  - The date of the scan

  - The duration of the scan

  - The number of hosts scanned in parallel

  - The number of checks done in parallel");

  exit(0);
}

include('plugin_feed_info.inc');
include('global_settings.inc');

be_silent = script_get_preference("Be silent");
if("yes" >< be_silent)exit(0);

version = OPENVAS_VERSION;

if(isnull(version)) {
 version = "Unknown";
}

report = 'Information about this scan : \n\n';
report += 'Scanner version : ' + version + '\n';

if ( PLUGIN_SET )
{
 report += 'NVT feed version : ' + PLUGIN_SET     + '\n';
 report += 'Type of NVT feed : ' + PLUGIN_FEED    + '\n';
}

report += 'Scanner IP : ' + this_host()    + '\n';


list = get_kb_list("Host/scanners/*");
if ( ! isnull(list) )
{
 foreach item ( keys(list) )
 {
  item -= "Host/scanners/";
  scanners += item + ' ';
 }

 report += 'Port scanner(s) : ' + scanners + '\n';
}


range = get_preference("port_range");
if ( ! range ) range = "(?)";
report += 'Port range : ' + range + '\n';

report += 'Report Verbosity : ';
report += report_verbosity + '\n';

report += 'Safe checks : ';
if ( safe_checks() ) report += 'yes\n';
else report += 'no\n';

report += 'Max hosts : ' + get_preference("max_hosts") + '\n';
report += 'Max checks : ' + get_preference("max_checks") + '\n';


start = get_kb_item("/tmp/start_time");

if ( start )
{
 time = localtime(start);
 if ( time["min"] < 10 ) zero = "0";
 else zero = NULL;

 report += 'Scan Start Date : ' + time["year"] + '/' + time["mon"] + '/' + time["mday"] + ' ' + time["hour"] + ':' + zero + time["min"] + '\n';
}

if ( ! start ) scan_duration = 'unknown (ping_host.nasl not launched?)';
else           scan_duration = string (unixtime() - start, " sec");

report += 'Scan duration : ' + scan_duration + '\n';

log_message(port:0, data:report);
