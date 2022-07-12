###############################################################################
# OpenVAS Vulnerability Test
#
# Nmap (NASL wrapper)
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Slight changes by Vlatko Kosturjak <kost@linux.hr>
# Support for network level scans added by
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

# nb: Keep above the description part as it is used there
include("misc_func.inc");
include("version_func.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14259");
  script_version("2019-05-07T10:42:32+0000");
  script_tag(name:"last_modification", value:"2019-05-07 10:42:32 +0000 (Tue, 07 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Nmap (NASL wrapper)");
  script_category(ACT_SCANNER);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Port scanners");
  script_dependencies("toolcheck.nasl", "ping_host.nasl");
  script_mandatory_keys("Tools/Present/nmap");

  script_xref(name:"URL", value:"https://nmap.org/");

  script_add_preference(name:"TCP scanning technique :", type:"entry", value:"SYN scan");
  # TODO: script_add_preference(name:"TCP scanning technique :", type:"radio", value:"connect();SYN scan;FIN scan;Xmas Tree scan;SYN FIN scan;FIN SYN scan;Null scan;No TCP scan");

  script_add_preference(name:"Service scan", type:"checkbox", value:"no");
  script_add_preference(name:"RPC port scan", type:"checkbox", value:"no");
  script_add_preference(name:"Fragment IP packets (bypasses firewalls)", type:"checkbox", value:"no");
  script_add_preference(name:"Do not randomize the  order  in  which ports are scanned", type:"checkbox", value:"no");
  script_add_preference(name:"Source port :", type:"entry", value:"");
  script_add_preference(name:"Timing policy :", type:"entry", value:"Aggressive");

  script_add_preference(name:"Max Retries :", type:"entry", value:"");
  script_add_preference(name:"Host Timeout (ms) :", type:"entry", value:"");
  script_add_preference(name:"Min RTT Timeout (ms) :", type:"entry", value:"");
  script_add_preference(name:"Max RTT Timeout (ms) :", type:"entry", value:"");
  # nb: Note the comment on this preference in the script_get_preference() below
  script_add_preference(name:"Initial RTT timeout (ms) :", type:"entry", value:"");
  script_add_preference(name:"Ports scanned in parallel (max)", type:"entry", value:"");
  script_add_preference(name:"Ports scanned in parallel (min)", type:"entry", value:"");
  script_add_preference(name:"Minimum wait between probes (ms)", type:"entry", value:"");
  script_add_preference(name:"Maximum wait between probes (ms)", type:"entry", value:"");
  script_add_preference(name:"File containing grepable results : ", type:"file", value:"");
  script_add_preference(name:"Do not scan targets not in the file", type:"checkbox", value:"no");
  script_add_preference(name:"Data length : ", type:"entry", value:"");
  script_add_preference(name:"Run dangerous port scans even if safe checks are set", type:"checkbox", value:"no");
  script_add_preference(name:"Log nmap output", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This plugin runs nmap to find open ports.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("network_func.inc");

if( get_kb_item( "Host/dead" ) ) exit( 0 );

phase = 0;
if( defined_func( "scan_phase" ) ) {
  phase = scan_phase();
}

# Phases:
# 0: No network level scan requested or scanner does not support scan phases.
# 1: Network level scan requested, we need to scan network_targets instead
#    of the "real" target and need to store the results prefixed with IP.
# 2: Network level scan was requested and completed.
# If we already did a network level scan, the results are in the DB and
# there is no point in scanning this individual host again.
# Just read and report the results for this host.
if( phase == 2 ) {
  ports = get_kb_list( "Ports/tcp/*" );
  foreach portstr( keys( ports ) ) {
    port = split( portstr, sep:"/", keep:FALSE );
    scanner_add_port( proto:"tcp", port:port[2] );
  }
  exit( 0 );
}

tmpfile = NULL;

function on_exit() {
  if( tmpfile && file_stat( tmpfile ) )
    unlink( tmpfile );
}

safe_opt = script_get_preference("Run dangerous port scans even if safe checks are set");
if( safe_opt && "yes" >< safe_opt )
  safe = 0;
else
  safe = safe_checks();

if( phase == 0 ) {

  ip     = get_host_ip();
  esc_ip = "";
  l = strlen( ip );

  for( i = 0; i < l; i++ ) {

    if( ip[i] == '.' )
      esc_ip = strcat( esc_ip, "\." );
    else
      esc_ip = strcat( esc_ip, ip[i] );

  }
} else {
  ip     = "network";
  esc_ip = "network";
}

res = script_get_preference_file_content( "File containing grepable results : " );
res = egrep( pattern:"Host: +" + esc_ip + " ", string:res );
if( ! res ) {

  opt = script_get_preference( "Do not scan targets not in the file" );
  if( "yes" >< opt )
    exit( 0 );

  i = 0;
  argv[i++] = "nmap";

  if( TARGET_IS_IPV6() )
    argv[i++] = "-6";

  argv[i++] = "-n";
  argv[i++] = "-Pn"; # Nmap ping is not reliable
  argv[i++] = "-oG";

  tmpdir = get_tmp_dir();
  if( tmpdir && strlen( tmpdir ) ) {
    tmpfile = strcat( tmpdir, "nmap-", ip, "-", rand() );
    fwrite( data:" ", file:tmpfile ); # make sure that tmpfile could be created. Then we can check that tmpfile exist with file_stat().
  }

  if( tmpfile && file_stat( tmpfile ) )
    argv[i++] = tmpfile;
  else
    argv[i++] = "-";

  port_range = get_preference( "port_range" );

  if( "T:" >< port_range ) {
    p = script_get_preference( "TCP scanning technique :" );

    if( p != "No TCP scan" ) {

      if( p == "SYN scan" || p == "SYN FIN scan" )
        argv[i++] = "-sS";
      else if( p == "FIN scan" || p == "FIN SYN scan" )
        argv[i++] = "-sF";
      else if( p == "Xmas Tree scan" )
        argv[i++] = "-sX";
      else if( p == "Null scan" )
        argv[i++] = "-sN";
      else
        argv[i++] = "-sT";

      if( p == "FIN SYN scan" || p == "SYN FIN scan" ) {
        argv[i++] = "--scanflags";
        argv[i++] = "SYNFIN";
      }
    }
  }

  # UDP & RPC scans or fingerprinting may kill a buggy IP stack
  if( ! safe ) {

    p = script_get_preference( "Service scan" );
    if( "yes" >< p )
      argv[i++] = "-sV";

    p = script_get_preference( "RPC port scan" );
    if( "yes" >< p )
      argv[i++] = "-sR";

    p = script_get_preference("Fragment IP packets (bypasses firewalls)");
    if( "yes" >< p )
      argv[i++] = "-f";
  }

  if( port_range ) { # Null for command line tests only

    if( "U:" >< port_range )
      argv[i++] = "-sU";

    argv[i++] = "-p";
    argv[i++] = port_range;
  }

  p = script_get_preference( "Do not randomize the  order  in  which ports are scanned" );
  if( "yes" >< p )
    argv[i++] = "-r";

  p = script_get_preference( "Source port :" );
  if( p =~ '^[0-9]+$' ) {
    argv[i++] = "-g";
    argv[i++] = p;
  }

  p = get_preference( "source_iface" );
  if( p =~ '^[0-9a-zA-Z:_]+$' ) {
    argv[i++] = "-e";
    argv[i++] = p;
  }

  # We should check the values when running in "safe checks".
  custom_policy = FALSE;

  p = script_get_preference( "Max Retries :" );
  if( p =~ '^[0-9]+$' ) {
    argv[i++] = "--max-retries";
    argv[i++] = p;
    custom_policy = TRUE;
  }

  p = script_get_preference( "Host Timeout (ms) :" );
  if( p =~ '^[0-9]+$' ) {
    argv[i++] = "--host-timeout";
    argv[i++] = p + 'ms';
    custom_policy = TRUE;
  }

  p = script_get_preference( "Min RTT Timeout (ms) :" );
  if( p =~ '^[0-9]+$' ) {
    argv[i++] = "--min-rtt-timeout";
    argv[i++] = p + 'ms';
    custom_policy = TRUE;
  }

  p = script_get_preference( "Max RTT Timeout (ms) :" );
  if( p =~ '^[0-9]+$' ) {
    argv[i++] = "--max-rtt-timeout";
    argv[i++] = p + 'ms';
    custom_policy = TRUE;
  }

  # nb: The lowercase t in timeout is expected here as it was used in the initial script_add_preference and can't be changed there.
  p = script_get_preference( "Initial RTT timeout (ms) :" );
  if( p =~ '^[0-9]+$' ) {
    argv[i++] = "--initial-rtt-timeout";
    argv[i++] = p + 'ms';
    custom_policy = TRUE;
  }

  min = 1;
  p = script_get_preference( "Ports scanned in parallel (min)" );
  if( p =~ '^[0-9]+$' ) {
    argv[i++] = "--min-parallelism";
    argv[i++] = p;
    min       = p;
    custom_policy = TRUE;
  }

  p = script_get_preference( "Ports scanned in parallel (max)" );
  if( p =~ '^[0-9]+$' ) {
    argv[i++] = "--max-parallelism";
    if( p < min )
      p = min;
    argv[i++] = p;
    custom_policy = TRUE;
  }

  p = script_get_preference( "Minimum wait between probes (ms)" );
  if( p =~ '^[0-9]+$' ) {
    argv[i++] = "--scan-delay";
    argv[i++] = p;
    custom_policy = TRUE;
  }

  p = script_get_preference( "Maximum wait between probes (ms)" );
  if( p =~ '^[0-9]+$' ) {
    argv[i++] = "--max-scan-delay";
    argv[i++] = p + 'ms';
    custom_policy = TRUE;
  }

  if( ! custom_policy ) {
    timing_templates = make_array( "Paranoid", 0,
                                   "Sneaky", 1,
                                   "Polite", 2,
                                   "Normal", 3,
                                   "Aggressive", 4,
                                   "Insane", 5 );

    p = script_get_preference( "Timing policy :" );
    if( isnull( p ) )
      p = "Normal";

    timing = timing_templates[p];

    if( ! isnull( timing ) ) {
      _timing   = "-T" + timing;
      argv[i++] = _timing;
      # For passing it to gb_nmap_os_detection, find_service_nmap.nasl and nmap_mac.nasl
      replace_kb_item( name:"Tools/nmap/timing_policy", value:_timing );
    }
  }

  p = script_get_preference( "Data length : " );
  if( p =~ '^[0-9]+$' ) {
    argv[i++] = "--data-length";
    argv[i++] = p;
    custom_policy = TRUE; # This is expected to be here as it doesn't affect the timing policies above
  }

  p = script_get_preference( "Log nmap output" );
  if( "yes" >< p ) {
    argv[i++]  = "-vv";
    log_output = TRUE;
  }

  if( phase == 1 )
    argv[i++] = network_targets();
  else
    argv[i++] = ip;

  scanner_status( current:0, total:65535 );
  res = pread( cmd:"nmap", argv:argv, cd:1 );

  if( "You requested a scan type which requires root privileges" >< res ) {
    log_message( port:0, data:"ERROR: You requested a Nmap scan type which requires root privileges but scanner is running under an unprivileged user. Start scanner as root or use a different portrange to get this scan working.");
    exit( 0 );
  }

  if( log_output ) {
    log_message( port:0, data:"nmap command: " + join( list:argv ) + '\n\n' + res );
  }

  if( tmpfile && file_stat( tmpfile ) )
    res = fread( tmpfile );

  if( ! res ) {
    if( tmpfile )
      report = "ERROR: Failed to read the file '" + tmpfile + "' containing the results of nmap.";
    else
      report = "ERROR: Failed to read the response of nmap. Maybe the nmap process timed out or was aborted?";
    log_message( port:0, data:report );
    exit( 0 ); # error
  }
}

if( phase == 0 ) {
  # TODO: Verify this pattern against newer and older nmap versions.
  # It seems at least in nmap 7.70 this text isn't included in the -oG output.
  if( egrep( string:res, pattern:'^# +Ports scanned: +TCP\\(65535;' ) )
    full_scan = TRUE;
  else
    full_scan = FALSE;

  res = egrep( pattern:"Host: +" + esc_ip + " ", string:res );
  if( ! res ) {
    mark_dead = get_kb_item( "/ping_host/mark_dead" );
    if( "yes" >< mark_dead )
      set_kb_item( name:"Host/dead", value:TRUE );
    exit( 0 ); # Host isn't alive / no ports open. Just exit here...
  }

  res = ereg_replace( pattern:'Host: +[0-9.]+ .*[ \t]+Ports: +', string:res, replace:"" );
  # Fields:
  # port_nb/state/protocol/owner/port_name/rpc_name/service/
  # Example:
  # Host: 127.0.0.1 ()      Ports: 111/open/tcp/bin/rpcbind (rpcbind V2)/(rpcbind:100000*2-2)/2 (rpc #100000)/, 111/open/udp//rpcbind (rpcbind V2)/(rpcbind:100000*2-2)/2 (rpc #100000)/, 113/open/tcp/root/ident //Linux-identd/, 119/open/tcp/root/nntp //Leafnode NNTPd 1.9.49.rel/, 123/open/udp//ntp ///, 137/open/udp//netbios-ns //Samba nmbd (host: CASSEROLE workgroup: MAISON)/, 138/open/udp//netbios-dgm ///, 139/open/tcp/root/netbios-ssn //Samba smbd 3.X (workgroup: MAISON)/      Ignored State: closed (194)

  scanned       = FALSE;
  udp_scanned   = FALSE;
  ident_scanned = FALSE;

  foreach blob( split( res, sep:',', keep:FALSE ) ) {
    v = eregmatch( string:blob, icase:TRUE, pattern:"^(Host: .*:)? *([0-9]+)/([^/]+)/([^/]+)/([^/]*)/([^/]*)/([^/]*)/([^/]*)/?" );
    if( ! isnull( v ) ) {

      port   = v[2];
      status = v[3];
      proto  = v[4];
      owner  = v[5];
      svc    = v[6];
      rpc    = v[7];
      ver    = v[8];

      if( "open" >< status ) # nmap 3.70 says "open|filtered" on UDP
        scanner_add_port( proto:proto, port:port );

      if( owner ) {
        log_message( port:port, proto:proto, data:"This service is owned by user " + owner );
        set_kb_item( name:"Ident/" + proto + "/" + port, value:owner );
        ident_scanned = TRUE;
      }

      scanned = TRUE;
      if( proto == "udp" )
        udp_scanned = TRUE;

      if( strlen( rpc ) > 1 ) {
        r = ereg_replace( string:rpc, pattern:"\(([^:]+):.+\)", replace:"\1" );
        if( ! r )
          r = rpc;

        log_message( port:port, proto:proto, data:"The RPC service " + r + " is running on this port. If you do not use it, disable it, as it is a potential security risk" );
      }

      if( ver ) {
        ver = ereg_replace( pattern:"^([0-9-]+) +\((.+)\)$", string:ver, replace:"\2 V\1" );
        log_message( port:port, proto:proto, data:"Nmap has identified this service as " + ver );
        set_kb_item( name:'Nmap/' + proto + '/' + port + '/version', value:ver );
        if( svc !~ "\?$" )
          set_kb_item( name:'Nmap/' + proto + '/' + port + '/svc', value:svc );

        set_kb_item( name:"external_svc_ident/available", value:TRUE ); # mandatory_key for external_svc_ident.nasl
      }
    }
  }

  v = eregmatch( string:res, pattern:'Seq Index: ([^\t]+)' );
  if( ! isnull( v ) ) {

    idx = int( v[1] );

    if( idx == 9999999 ) {
      log_message( port:0, data:"The TCP initial sequence number of the remote host look truly random. Excellent!" );
      set_kb_item( name:"Host/tcp_seq", value:"random" );
    } else if( idx == 0 ) {
      set_kb_item( name:"Host/tcp_seq", value:"constant" );
    } else if( idx == 1 ) {
      set_kb_item( name:"Host/tcp_seq", value:"64000" );
    } else if( idx == 10 ) {
      set_kb_item( name:"Host/tcp_seq", value:"800" );
    } else if( idx < 75 ) {
      set_kb_item( name:"Host/tcp_seq", value:"time" );
    } else {
      log_message( port:0, data:"The TCP initial sequence number of the remote host are incremented by random positive values. Good!" );
      set_kb_item( name:"Host/tcp_seq", value:"random" );
    }
    set_kb_item( name:"Host/tcp_seq_idx", value:v[1] );
  }

  v = eregmatch( string:res, pattern:'IPID Seq: ([^\t]+)' );
  if( ! isnull( v ) )
    log_message( port:0, data:"The IP ID sequence generation is: " + v[1] );

  if( scanned ) {
    set_kb_item( name:"Host/scanned", value: TRUE );
    set_kb_item( name:'Host/scanners/nmap', value:TRUE );
  }

  if( udp_scanned )
    set_kb_item( name:"Host/udp_scanned", value:TRUE );

  if( full_scan ) {

    if( ident_scanned )
      set_kb_item( name:"Host/ident_scanned", value:TRUE );

    set_kb_item( name:"Host/full_scan", value:TRUE );
  }
} else if( phase == 1 ) {

  lines = split( res, sep:'\n', keep:FALSE );
  foreach blob( lines ) {
    c = split( blob, sep:"Ports: ", keep:FALSE );
    d = split( c[0], sep:" ", keep:FALSE );
    e = split( c[1], sep:", ", keep:FALSE );
    if( ! isnull( e ) ) {
      foreach f( e ) {
        g = split( f, sep:"/", keep:FALSE );
        set_kb_item( name:d[1] + "/Ports/tcp/" + g[0], value:1 );
      }
    }
  }
}

scanner_status( current:65535, total:65535 );
