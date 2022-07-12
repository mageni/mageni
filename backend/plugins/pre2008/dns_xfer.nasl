###############################################################################
# OpenVAS Vulnerability Test
#
# DNS AXFR
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
# Modified by Axel Nennker <axel@nennker.de>
# Modified by Erik Anderson <eanders@pobox.com>
# Modified by Pavel Kankovsky <kan@dcit.cz>
# Modified by Tim Brown <timb@openvas.org>
#
# Copyright:
# Copyright (C) 2000 j_lampe@bellsouth.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10595");
  script_version("2019-05-24T11:20:30+0000");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_cve_id("CVE-1999-0532");
  script_name("DNS AXFR");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 j_lampe@bellsouth.net");
  script_family("General");
  script_dependencies("dns_server.nasl", "msdns-server-hostname-disclosure.nasl");
  script_mandatory_keys("DNS/identified");

  script_tag(name:"impact", value:"A zone transfer will allow the remote attacker to instantly
  populate a list of potential targets. In addition, companies often use a naming convention
  which can give hints as to a servers primary application (for instance, proxy.company.com,
  payroll.company.com, b2b.company.com, etc.).

  As such, this information is of great use to an attacker who may use it to gain information
  about the topology of your network and spot new targets.");

  script_tag(name:"solution", value:"Restrict DNS zone transfers to only the servers that
  absolutely need it.");

  script_tag(name:"summary", value:"The remote name server allows DNS zone transfers to be performed.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("global_settings.inc");
include("dump.inc");
include("misc_func.inc");

function myintstring_to_int( mychar ) {

  myintrray = "0123456789";
  for( q = 0; q < 10; q++ ) {
    if( myintrray[q] == mychar ) return( q + 48 );
  }
}

#create UDP DNS header
get_host_by_addr = raw_string( 0xB8, 0x4C, 0x01, 0x00, 0x00, 0x01,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

#Add in reversed octet order IP addr
myip = get_host_ip();
len = strlen( myip );
counter = 0;

for( flag = len; flag > 0; flag = flag - 1 ) {

  if( myip[flag-1] == "." ) {
    get_host_by_addr = get_host_by_addr + raw_string( counter );
    for( tcount = flag; tcount < flag + counter; tcount++ ) {
      mcount = temprray[tcount];
      get_host_by_addr = get_host_by_addr + raw_string( mcount );
    }
    for( mu = 0; mu < 15; mu++ ) {
      temprray[mu] = 0;
    }
    counter = 0;
  } else {
    temprray[flag-1] = myintstring_to_int( mychar:myip[flag-1] );
    counter++;
  }
}

get_host_by_addr = get_host_by_addr + raw_string( counter );
for( tcount = flag; tcount < flag + counter; tcount++ ) {
  mcount = temprray[tcount];
  get_host_by_addr = get_host_by_addr + raw_string( mcount );
}

#add in in-addr.arpa
get_host_by_addr = get_host_by_addr +  raw_string( 0x07, 0x69, 0x6E, 0x2D, 0x61, 0x64,
                                                   0x64, 0x72, 0x04, 0x61, 0x72, 0x70,
                                                   0x61 );

get_host_by_addr = get_host_by_addr + raw_string( 0x00, 0x00, 0x0C, 0x00, 0x01 );

# nb: big-endian 16-bit value (string s, offset o)
function ntohs( s, o ) {

  local_var ret_hi, ret_lo;

  ret_hi = ord( s[o] ) << 8;
  ret_lo = ord( s[o+1] );
  return( ret_hi + ret_lo );
}

# skip one chain of labels
# returns the new offset ("jump")
function skiplabels( buf, buflen, jump ) {

  local_var curlabel;

  while( jump < buflen ) {
    curlabel = ord( buf[jump] );
    if( curlabel == 0 ) {
      jump += 1;
      return( jump );
    }
    if( curlabel >= 0xc0 ) {
      jump += 2;
      return( jump );
    }
    jump += curlabel + 1;
  }
 return jump;
}

# nb: fetch one chain of labels
# returns the chain of labels (decompressed) or NULL if error
# skips "skip" leading labels
function fetchlabels( buf, buflen, jump, skip ) {

  local_var curlabel, result, iter;

  iter = 10;
  result = "";
  while( jump < buflen && iter > 0 ) {
    curlabel = ord( buf[jump] );
    if( curlabel == 0 ) {
      # that's all folks!
      if( debug_level ) display("debug: fetchlabels >>", result, "<< (len=", strlen(result), ")\n");
      return( result );
    }
    else if (curlabel < 0xc0) {
      # new label
      if( jump + curlabel + 1 > buflen ) return( NULL );
      if( isnull( skip ) || skip <= 0 )
        result = strcat( result, substr( buf, jump, jump + curlabel ) );
      else
        skip -= 1;
      jump += curlabel + 1;
    }
    else {
      # compressed indirect reference
      iter -= 1; # prevent endless loop
      if( jump + 2 > buflen ) return( NULL );
      jump = ntohs( s:buf, o:jump ) & 0x3fff;
    }
  }
  return( NULL );
}

port = get_kb_item( "Services/udp/domain" );
if ( ! port ) port = 53;

if( ! get_udp_port_state( port ) ) exit( 0 );

# send UDP PTR query
soc = open_sock_udp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:get_host_by_addr );
myreturn = recv( socket:soc, length:4096 );
myretlen = strlen( myreturn );

if( debug_level ) display("debug: got UDP answer myretlen=", myretlen, "\n");

close( soc );
if( myretlen < 12 ) exit( 0 );

# analyze UDP answer
# maybe save this info to kb as "Port/udb/53=1" if (strlen(myreturn>0))
ancount = ntohs( s:myreturn, o:6 );
if( ancount < 1 ) exit( 0 );

# skip header and query section
jump = 12;
if( debug_level > 1 ) fetchlabels( buf:myreturn, buflen:myretlen, jump:jump );
jump = skiplabels( buf:myreturn, buflen:myretlen, jump:jump );
jump += 4;

# walk through answers
# we look for IN PTR
found_answer = 0;
for( theta = 0; ( theta < ancount ) && ( jump < myretlen ); theta ++ ) {

  if( debug_level > 1 ) fetchlabels( buf:myreturn, buflen:myretlen, jump:jump );

  jump = skiplabels( buf:myreturn, buflen:myretlen, jump:jump );
  jump += 10;

  if( jump < myretlen ) {
    rtype  = ntohs( s:myreturn, o:jump-10 );
    rclass = ntohs( s:myreturn, o:jump-8 );

    if( debug_level ) display( "debug: UDP answer RR rtype=", rtype, " rclass=", rclass, "\n" );

    # nb: check type 12 (PTR) & class 1 (IN)
    # XXX we might get multiple PTR records
    if( rtype == 12 && rclass == 1 ) {
      found_answer = 1;
      break;
    }
    jump += ntohs( s:myreturn, o:jump-2 );
  }
}

if( ! found_answer ) exit( 0 );
domain = fetchlabels( buf:myreturn, buflen:myretlen, jump:jump, skip:1 );
if( isnull( domain ) || domain == "" ) exit( 0 );

domain = bin2string( ddata:domain, noprint_replacement:'.' );

#start putting together the TCP DNS zone transfer request
pass_da_zone = strcat( raw_string( 0x68, 0xB3,   # ID
                                   0x00, 0x00,   # QR|OC|AA|TC|RD|RA|Z|RCODE
                                   0x00, 0x01,   # QDCOUNT
                                   0x00, 0x00,   # ANCOUNT
                                   0x00, 0x00,   # NSCOUNT
                                   0x00, 0x00 ), # ARCOUNT
                       domain,
                       raw_string( 0x00,         # NULL Terminator
                                   0x00, 0xFC,   # QTYPE=252=ZoneTransfer
                                   0x00, 0x01 )  # QCLASS=1=Internet
                      );

len = strlen( pass_da_zone );
len_hi = len / 256;
len_lo = len % 256;
pass_da_zone = raw_string( len_hi, len_lo ) + pass_da_zone;

if( ! get_port_state( port ) ) exit( 0 );
soctcp = open_sock_tcp( port );
if( ! soctcp ) exit( 0 );

# send TCP AXFR query
send( socket:soctcp, data:pass_da_zone );
incoming = recv( socket:soctcp, length:2 );
if( strlen( incoming ) < 2 ) exit( 0 );
len = ntohs( s:incoming, o:0 );

if( debug_level ) display( "debug: got TCP answer len=", len, "\n" );

# don't want an infinite loop, if answer is illegal
if( len < 0 ) exit( 0 );

# only interested in incoming[7]
if( len > 8 ) len = 8;
incoming = recv( socket:soctcp, length:len, min:len );
close( soctcp );

# analyze TCP answer
ancount = ntohs( s:incoming, o:6 );
if( ancount >= 1 ) {

  domain = str_replace( string:domain, find:"	",replace:"" );
  domain = str_replace( string:domain, find:" ",replace:"" );

  report = string( "It was possible to initiate a zone transfer for the domain '", domain, "'\n" );
  log_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );