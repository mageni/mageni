###############################################################################
# OpenVAS Vulnerability Test
# $Id: find_service_nmap_wrapped.nasl 12934 2019-01-03 20:41:17Z cfischer $
#
# Service Detection (wrapped) with nmap
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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

# For those who wish to go digging, please note that this is potentially
# the second time nmap will be launched with -sV (service identification)
# parameters.  The first timeout can be in "nmap.nasl". We cannot, however,
# rely on that pass for a number of reasons:
#    1. We may not be running that port scanner.
#    2. We only want to run AFTER find_service* scripts have executed,
#       along with a whole host of other specialty service identification
#       scripts. Our objective is to minimize nmap service identification
#       execution time, and only run it on services that remain unidentified

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108525");
  script_version("$Revision: 12934 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-03 21:41:17 +0100 (Thu, 03 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-03 20:47:03 +0100 (Thu, 03 Jan 2019)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection (wrapped) with nmap");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Service detection");
  script_require_ports("Services/wrapped");
  # nb: Keep unknown_services.nasl in here so the nmap detection and service registration
  # doesn't interfere with a previous reporting.
  script_dependencies("toolcheck.nasl", "unknown_services.nasl");
  script_mandatory_keys("Tools/Present/nmap");

  script_tag(name:"summary", value:"This plugin performs service detection by launching nmap's
  service probe (nmap -sV) against ports that are running services marked as 'wrapped' and where
  unidentified so far.

  The actual reporting takes place in the separate NVT 'Unknown OS and Service Banner Reporting'
  OID: 1.3.6.1.4.1.25623.1.0.108441.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_timeout(900); #TBD: This NVT had a timeout of 0 which means currently the default of 320. Assuming 900 for now

  exit(0);
}

include("revisions-lib.inc");
include("misc_func.inc");

ver = pread( cmd:"nmap", argv:make_list( "nmap", "-V" ) );
extract = eregmatch( string:ver, pattern:".*nmap version ([0-9.]+).*", icase:TRUE );

# Only run if we have nmap 4.62 or later available.
# Yes - this is arbitrary. We've tested with 4.62 and 5.00
if( isnull( extract ) || revcomp( a:extract[1], b:"4.62" ) < 0 ) {
  exit( 0 );
}

# This will fork. Potential issue if large # of wrapped services.
port = get_kb_item( "Services/wrapped" );
if( ! port )
  exit( 0 );

if( ! get_port_state( port ) )
  exit( 0 );

if( ! service_is_unknown( port:port ) )
  exit( 0 );

# nb: Check if we can still open that port before throwing nmap on it
soc = open_sock_tcp( port, transport:ENCAPS_IP );
if( ! soc )
  exit( 0 );
else
  close( soc );

i = 0;
ip = get_host_ip();
argv[i++] = "nmap";

if( TARGET_IS_IPV6() )
  argv[i++] = "-6";

# Apply the chosen nmap timing policy from nmap.nasl here as well
timing_policy = get_kb_item( "Tools/nmap/timing_policy" );
if( timing_policy =~ '^-T[0-5]$' )
  argv[i++] = timing_policy;

source_iface = get_preference( "source_iface" );
if( source_iface =~ '^[0-9a-zA-Z:_]+$' ) {
  argv[i++] = "-e";
  argv[i++] = source_iface;
}

argv[i++] = "-sV";
argv[i++] = "-Pn";
argv[i++] = "-p";
argv[i++] = port;
argv[i++] = "-oG";
argv[i++] = "-";
argv[i++] = ip;
res = pread( cmd:"nmap", argv:argv );

# Extract port and service name from results
extract = eregmatch( string:res, pattern:".*Ports: ([0-9]+)/+open/[^/]*/[^/]*/([^/]*)/.*" );

servicesig = extract[2];

# If nmap wasn't sure, it may have added '?' to end of servicesig. Strip it
len = strlen( servicesig );

if( len > 0 ) {
  lastchar = substr( servicesig, len - 1 );
  if( lastchar == "?" ) {
    servicesig = substr( servicesig, 0, len - 2 );
    guess = TRUE;
  }
}

if( strlen( servicesig ) > 0 ) {

  set_kb_item( name:"unknown_os_or_service/available", value:TRUE ); # Used in gb_unknown_os_service_reporting.nasl

  report = 'Nmap service detection (wrapped) result for this port: ' + servicesig;

  if( guess ) {
    command = "nmap -sV -Pn -p " + port + " " + ip;
    report += '\n\nThis is a guess. A confident identification of the service was not possible.\n\n';
    report += "Hint: If you're running a recent nmap version try to run nmap with the following command: '" + command;
    report += "' and submit a possible collected fingerprint to the nmap database.";
  }

  set_kb_item( name:"unknown_service_report/nmap/wrapped/" + port + "/report", value:report );
}

exit( 0 );