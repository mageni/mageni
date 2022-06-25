###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_os_detection.nasl 11943 2018-10-17 14:46:48Z cfischer $
#
# Nmap OS Identification (NASL wrapper)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
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

# Nmap can be found at :
# <http://nmap.org>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108021");
  script_version("$Revision: 11943 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 16:46:48 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-21 12:08:04 +0100 (Mon, 21 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Nmap OS Identification (NASL wrapper)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  # This should run after os_fingerprint.nasl so we're only running it if its really required
  script_dependencies("secpod_open_tcp_ports.nasl", "toolcheck.nasl", "os_fingerprint.nasl");
  script_mandatory_keys("TCP/PORTS", "Tools/Present/nmap");

  script_xref(name:"URL", value:"https://nmap.org/book/man-os-detection.html");
  script_xref(name:"URL", value:"https://nmap.org/book/osdetect.html");

  script_add_preference(name:"Guess OS more aggressively (safe checks off only)", type:"checkbox", value:"no");
  script_add_preference(name:"Guess OS more aggressively even if safe checks are set", type:"checkbox", value:"no");
  script_add_preference(name:"Run routine", type:"checkbox", value:"yes");

  script_tag(name:"summary", value:"This plugin runs nmap to identify the remote Operating System.

  NOTE: This routine is only started as a last fallback if other more reliable OS detection methods failed.

  This routine also has a few additional drawbacks:

  - Depending on the exposed services on the target it might take a considerable amount of time to complete

  - It needs to conntect to TCP ports which might be not within the configured port list of this target

  - It might interfere with other service detection methods of the scanner

  Due to this it is possible to disable this routine via the script preferences.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("network_func.inc");

SCRIPT_DESC = "Nmap OS Identification (NASL wrapper)";

if( get_kb_item( "Host/dead" ) ) exit( 0 );

# Allow the user to disable this routine for the the reasons explained
# in the sript summary.
run_routine = script_get_preference( "Run routine" );
if( ! run_routine ) run_routine = "yes";
if( run_routine == "no" ) exit( 0 );

# nb: We only want to run this NVT as a "last fallback" if all of the other OS
# detections failed. This is due to the reasons explained in the sript summary.
# Furthermore we want to run it if os_fingerprint.nasl is the only detection
# method and has a low confidence (it isn't that reliable these days...).
reports = get_kb_list( "os_detection_report/reports/*" );

# We only have one OS detection, check if its from ICMP based OS Fingerprinting (OID: 1.3.6.1.4.1.25623.1.0.102002)
if( reports && max_index( keys( reports ) ) == 1 ) {

  # We have one result which is not ICMP OS detection so we don't want to start
  if( ! in_array( search:"1.3.6.1.4.1.25623.1.0.102002", array:reports, part_match:TRUE ) ) exit( 0 );

  # nb: This key might have multiple entries, don't use get_kb_item here to avoid forking.
  confidence = get_kb_list( "Host/OS/ICMP/Confidence" );

  # nb: This checks if the ICMP OS detection has multiple OS detected
  if( confidence && max_index( keys( confidence ) ) == 1 ) {
    # We only want to start if the confidence is low
    if( int( confidence["Host/OS/ICMP/Confidence"] ) >= 95 ) exit( 0 );
  }
  # If the above (multiple OS by ICMP OS detection) is the case we want to start this routine
} else if( reports && max_index( keys( reports ) ) > 1 ) {
  # We have multiple detections from other routines so we don't want to start
  exit( 0 );
}

# If we're reaching this part none of the explained pattern above matches and we're running a nmap based OS detection as a fallback

# -O needs at least one open and one closed TCP port
openPorts = get_all_tcp_ports_list();
if( ! openPorts || max_index( openPorts ) == 0 ) exit( 0 );

tmpfile = NULL;

function on_exit() {
  if( tmpfile && file_stat( tmpfile ) ) unlink( tmpfile );
}

safe_opt = script_get_preference( "Guess OS more aggressively even if safe checks are set" );
if( safe_opt && "yes" >< safe_opt ) {
  safe = 0;
} else {
  safe = safe_checks();
}

ip = get_host_ip();

i = 0;
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

argv[i++] = "-n";
argv[i++] = "-Pn"; # Also run if ping failed
argv[i++] = "-sV"; # nmap is able to detect the OS from the service scan like: Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel:3.2.40
argv[i++] = "-oN"; # -oG currently doesn't have the CPE in its output

tmpdir = get_tmp_dir();
if( tmpdir && strlen( tmpdir ) ) {
  tmpfile = strcat( tmpdir, "nmap-", ip, "-", rand() );
  fwrite( data:" ", file:tmpfile ); # make sure that tmpfile could be created. Then we can check that tmpfile exist with file_stat().
}

if( tmpfile && file_stat( tmpfile ) ) {
  argv[i++] = tmpfile;
} else {
  argv[i++] = "-";
}

argv[i++] = "-O";
argv[i++] = "--osscan-limit"; # Limit OS detection to promising targets (nmap will exit if not at least one open and one closed TCP port was found)

if( ! safe ) {
  p = script_get_preference( "Guess OS more aggressively (safe checks off only)" );
  if( "yes" >< p ) argv[i++] = "--osscan-guess";
}

argv[i++] = "-p";
portList = NULL;

foreach port( openPorts ) {

  # Removing 27960 which is known to crash (see find_service.nasl)
  if( port == "27960" ) continue;

  if( is_fragile_port( port:port ) ) continue;

  if( isnull ( portList ) ) {
    portList = port;
  } else {
    portList += "," + port;
  }
}

# Also add a few low-ports as nmap OS detection behaves strange with only closed/filtered high ports
foreach port( make_list( "21", "22", "25", "80", "135", "139", "443", "445" ) ) {

  if( is_fragile_port( port:port ) ) continue;

  if( ! in_array( search:port, array:openPorts ) ) {
    # openPorts = get_all_tcp_ports_list(); above might be an empty list in some special cases causing
    # portList to be NULL. So make sure to create a valid portList in this case.
    if( isnull ( portList ) ) {
      portList = port;
    } else {
      portList += "," + port;
    }
  }
}

# -O needs at least one open and one closed TCP port so adding five potentially closed ports here

# Amount of closed ports to add. Don't add more then 5 as random ports between 1xxxx and 5xxxx are chosen down below based on this
numClosedPorts = 3;

# Choose a high port for the needed closed port
for( j = 1; j <= numClosedPorts; j++ ) {

  closedPort = rand_str( length:( 4 ), charset:'0123456789' );

  # Choose the closed port in the range of i0000 - i9999 and make sure its not already in the list.
  # nb: This might break if someone is specifying all ports in the range of e.g. 10000-19999 as fragile
  # but this is quite unlikely...
  while( j + closedPort >< portList || is_fragile_port( port:j + closedPort ) ) {
    closedPort = rand_str( length:( 4 ), charset:'0123456789' );
  }
  portList += "," + j + closedPort;
}

argv[i++] = portList;

argv[i++] = ip;

res = pread( cmd:"nmap", argv:argv, cd:1 );

if( "TCP/IP fingerprinting (for OS scan) requires root privileges." >< res ) {
  log_message( port:0, data:"ERROR: TCP/IP fingerprinting (for OS scan) requires root privileges but scanner is running under an unprivileged user. Start scanner as root to get this scan working.");
  exit( 0 );
}

if( tmpfile && file_stat( tmpfile ) ) {
  res = fread( tmpfile );
}

if( ! res ) exit( 0 ); # error

# We don't want to report the OS if nmap is not absolutely sure
if( "JUST GUESSING" >< res || "test conditions non-ideal" >< res || "No exact OS matches for host" >< res ) {

  # Remove unknown fingerprints as we don't want to flood the report with this data
  pattern = "([0-9]+)( (service|services) unrecognized despite returning data).*\);";
  if( eregmatch( pattern:pattern, string:res ) ) {
    res = ereg_replace( string:res, pattern:pattern, replace:"*** unknown fingerprints replaced ***" );
  }

  register_unknown_os_banner( banner:res, banner_type_name:"Nmap TCP/IP fingerprinting", banner_type_short:"nmap_os" );
  exit( 0 );
}

# Examples:
# OS details: Linux 3.8 - 4.5
# OS details: Microsoft Windows Server 2008 SP2 or Windows 10 Tech Preview, Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows 8, or Windows 8.1 Update 1
osTxt = eregmatch( string:res, pattern:"OS details: ([ -~]+)" );

# Examples:
# OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
# OS CPE: cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_7::- cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_8
osCpe = eregmatch( string:res, pattern:"OS CPE: ([ -~]+)" );
sep = " "; # Separator to split multiple CVEs

if( isnull( osTxt ) || isnull( osCpe ) ) {

  # Example from -sV: "Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel:2, cpe:/o:linux:linux_kernel:3.2.40"
  osTxt = eregmatch( string:res, pattern:"OS: ([ -~]+);");
  osCpe = eregmatch( string:res, pattern:"CPE: ([ -~]+)" );
  sep = ", "; # Separator to split multiple CVEs
}

if( ! isnull( osTxt ) && ! isnull( osCpe ) ) {

  cpes = split( osCpe[0], sep:sep, keep:FALSE );
  cpe = cpes[max_index( cpes ) - 1];

  if( "linux" >< tolower( osTxt[1] ) || "linux" >< cpe ) {
    osname   = osTxt[1];
    oscpe    = cpe;
    runs_key = "unixoide";
  } else if( "windows" >< tolower( osTxt[1] ) || "windows" >< cpe ) {
    osname = osTxt[1];
    oscpe  = cpe;
    # nb: Sometimes nmap is reporting e.g. the following:
    # OS details: Microsoft Windows Server 2008 SP2 or Windows 10 Tech Preview, Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows 8, or Windows 8.1 Update 1
    # OS CPE: cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_7::- cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_8
    # In this case we don't want to report a specific CPE as we would e.g. mark Windows 8 as EOL (if chosen) where the system is actually running Windows 7 with SP1
    if( max_index( cpes ) > 3 ) {
      osname = "Microsoft Windows";
      oscpe  = "cpe:/o:microsoft:windows";
    }
    runs_key = "windows";
  } else {
    osname   = osTxt[1];
    oscpe    = cpe;
    runs_key = "unknown";
  }
  register_and_report_os( os:osname, cpe:oscpe, banner_type:"Nmap TCP/IP fingerprinting", banner:'\n' + osTxt[0] + '\n' + osCpe[0], desc:SCRIPT_DESC, runs_key:runs_key );
}

exit( 0 );
