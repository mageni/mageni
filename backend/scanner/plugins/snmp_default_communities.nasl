###############################################################################
# OpenVAS Vulnerability Test
# $Id: snmp_default_communities.nasl 13440 2019-02-04 14:16:18Z cfischer $
#
# Default community names of the SNMP Agent
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Modifications :
# 02/22/2000, Renaud Deraison : added more communities
# 06/08/2000, Renaud Deraison : fixed a problem in the packets sent
# 24/02/2002, Richard Lush    : Modified to find the error code
# 08/03/2002, Axel Nennker    : cisco ILMI solution
# 23/05/2002, Axel Nennker    : ONE report for this plugin
#                   some stupid HP Printers answer to every community
# 20/04/2005, Javier Fernandez-Sanguino, added more communities for
#                   Cisco's aironet
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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

# References:
#
# From: Raphael Muzzio (rmuzzio_at_ZDNETMAIL.COM)
# Date: Nov 15 1998
# To: bugtraq@securityfocus.com
# Subject:  Re: ISS Security Advisory: Hidden community string in SNMP
# (http://lists.insecure.org/lists/bugtraq/1998/Nov/0212.html)
#
# Date: Mon, 5 Aug 2002 19:01:24 +0200 (CEST)
# From:"Jacek Lipkowski" <sq5bpf@andra.com.pl>
# To: bugtraq@securityfocus.com
# Subject: SNMP vulnerability in AVAYA Cajun firmware
# Message-ID: <Pine.LNX.4.44.0208051851050.3610-100000@hash.intra.andra.com.pl>
#
# From:"Foundstone Labs" <labs@foundstone.com>
# To: da@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: Foundstone Labs Advisory - Information Leakage in Orinoco and Compaq Access Points
# Message-ID: <9DC8A3D37E31E043BD516142594BDDFAC476B0@MISSION.foundstone.com>
#
# CC:da@securityfocus.com, vulnwatch@vulnwatch.org
# To:"Foundstone Labs" <labs@foundstone.com>
# From:"Rob Flickenger" <rob@oreillynet.com>
# In-Reply-To: <9DC8A3D37E31E043BD516142594BDDFAC476B0@MISSION.foundstone.com>
# Message-Id: <D8F6A4EC-ABE3-11D6-AF54-0003936D6AE0@oreillynet.com>
# Subject: Re: [VulnWatch] Foundstone Labs Advisory - Information Leakage in Orinoco and Compaq Access Points
#
# http://www.iss.net/issEn/delivery/xforce/alertdetail.jsp?id=advise15

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103914");
  script_version("$Revision: 13440 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-04 15:16:18 +0100 (Mon, 04 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check default community names of the SNMP Agent");
  script_category(ACT_SETTINGS);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("SNMP");
  script_dependencies("gb_open_udp_ports.nasl", "gb_default_credentials_options.nasl");
  script_require_udp_ports(161);
  script_exclude_keys("default_credentials/disable_brute_force_checks");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  login with default communities. Successful logins are storen in the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");

# If optimize_test = no
if( get_kb_item( "default_credentials/disable_brute_force_checks" ) )
  exit( 0 );

#nb: Don't use UDP/PORTS or get_snmp_port() as the check below is quite unreliable against other non-snmp UDP services
port = 161;
if (!get_udp_port_state(port))
  exit(0);

communities = make_list(
"Cisco router", # for Cisco equipment
"EyesOfNetwork", # Eyes of Network (EON)
"cable-docsis", # for Cisco equipment
"cascade", # for Lucent equipment
"comcomcom", # for 3COM AirConnect AP
"rmonmgmtuicommunity", # 2016/gb_cisco_sg220_cisco-sa-20160831-sps3.nasl
"ROUTERmate", # CVE-1999-0792
"tellmeyoursecrets", # BID 7081
"SmartScanServer", # Default from CVE-2016-6267
"wheel", # https://blogs.cisco.com/security/talos/rockwell-snmp-vuln
# From https://lkhill.com/brocade-vdx-snmp-changes/ and http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=mmr_kc-0127107
"ConvergedNetwork",
"secret c0de", # Advisories are showing differences between lower/uppercase and quotes/no quotes for these four communities:
'"secret c0de"',
"Secret C0de", # Brocade
'"Secret C0de"',
"common",
"FibreChannel",
# CVE-2002-1229, https://marc.info/?l=bugtraq&m=103470243012971&w=2
"diag",
"manuf",
"danger",
"xxyyzz",
# From https://github.com/fuzzdb-project/fuzzdb/blob/master/wordlists-misc/wordlist-common-snmp-community-strings.txt
"public",
"private",
"0",
"0392a0",
"1234",
"2read",
"4changes",
"ANYCOM", # for 3COM NetBuilder
"Admin",
"C0de",
"CISCO",
"CR52401",
"IBM",
"ILMI",
"Intermec",
"NoGaH$@!", # Avaya
"OrigEquipMfr", # Brocade
"PRIVATE",
"PUBLIC",
"Private",
"Public",
"SECRET",
"SECURITY",
"SNMP",
"SNMP_trap",
"SUN",
"SWITCH",
"SYSTEM",
"Secret",
"Security",
"s!a@m#n$p%c", # 2012/secpod_samsung_printer_snmp_auth_bypass_vuln.nasl
"Switch",
"System",
"TENmanUFactOryPOWER",
"TEST",
"access",
"adm",
"admin",
"agent",
"agent_steal", # CVE-2001-1210
"all",
# Advisories are showing differences between lower/uppercase and quotes/no quotes for these two communities:
"all private", # Solaris 2.5.1 and 2.6
'"all private"', # Solaris 2.5.1 and 2.6
"all public",
"apc", # for APC Web/SNMP Management Card AP9606
"bintec",
"blue", # HP JetDirect equipement
"c", # for Cisco equipment
"cable-d",
"canon_admin",
"cc", # for Cisco equipment
"cisco",
"community",
"core", # Cisco Aironet
"debug",
"default",
"dilbert",
"enable",
"field",
"field-service",
"freekevin", # CVE-2001-1210
"fubar", # CVE-2001-1210
"guest",
"hello",
"hp_admin",
"ibm",
"ilmi",
"intermec",
"internal", # HP JetDirect equipement
"l2",
"l3",
"manager",
"mngt",
"monitor",
"netman",
"network",
"none",
"openview",
"pass",
"password",
"pr1v4t3",
"proxy", # Cisco Aironet
"publ1c",
"read",
"read-only",
"read-write",
"readwrite",
"red",
"regional", # Cisco Aironet
"rmon",
"rmon_admin",
"ro",
"root",
"router",
"rw",
"rwa",
"san-fran",
"sanfran",
"scotty",
"secret", # for Cisco equipment
"security",
"seri",
"snmp",
"snmpd", # HP SNMP agent
"snmptrap",
"solaris",
"sun",
"superuser",
"switch",
"system",
"tech",
"test",
"test2",
"tiv0li",
"tivoli",
"trap",
"world",
"write", # for Cisco equipment
"xyzzy", # CVE-2001-1210
"yellow", # HP JetDirect equipement
# From http://www.phenoelit.org/dpl/dpl.html
"volition",
"MiniAP",
"snmp-Trap"
);

# Add device/host name
name = get_host_name();
if( name !~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" && ":" >!< name ) {
  # We have a name, not an IP/IPv6
  names[0] = name;
  dot = strstr( name, '.' );
  if( dot ) {
    name = name - dot; # Use short name
    names[1] = name;
  }

  foreach name( names ) {
    if( ! in_array( search:name, array:communities ) ) {
      communities = make_list( communities, name ); # The name is not already in the list
    }
  }
}

count = 0;

# We don't use the SNMP functions from snmp_func.inc since they are too slow for brute forcing
for( i = 0; communities[i]; i++ ) {

  community = communities[i];

  SNMP_BASE = 31;
  COMMUNITY_SIZE = strlen( community );

  sz = COMMUNITY_SIZE % 256;

  len = SNMP_BASE + COMMUNITY_SIZE;
  len_hi = len / 256;
  len_lo = len % 256;
  sendata = raw_string( 0x30, 0x82, len_hi, len_lo,
                        0x02, 0x01, 0x00, 0x04, sz );

  sendata = sendata + community +
            raw_string( 0xA1, 0x18, 0x02, 0x01, 0x01,
                        0x02, 0x01, 0x00, 0x02, 0x01,
                        0x00, 0x30, 0x0D, 0x30, 0x82,
                        0x00, 0x09, 0x06, 0x05, 0x2B,
                        0x06, 0x01, 0x02, 0x01, 0x05,
                        0x00 );


  dstport = port;
  soc[i] = open_sock_udp( dstport );
  send( socket:soc[i], data:sendata );
  usleep( 10000 ); # Cisco don't like to receive too many packets at the same time
}

for( j = 0; communities[j]; j++ ) {

  result = recv( socket:soc[j], length:200, timeout:1 );
  close( soc[j] );

  if( result ) {
    count++;
    set_kb_item( name:"SNMP/" + port + "/v12c/detected_community", value:communities[j] );
    set_kb_item( name:"SNMP/v12c/detected_community", value:TRUE );
  }
}

if( count > 4 ) {
  set_kb_item( name:"SNMP/" + port + "/v12c/all_communities", value:TRUE );
}

exit( 0 );
