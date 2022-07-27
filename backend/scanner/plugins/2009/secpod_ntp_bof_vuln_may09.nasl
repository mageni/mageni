###############################################################################
# OpenVAS Vulnerability Test
#
# NTP 'ntpd' Autokey Stack Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900652");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-05-22 08:49:17 +0200 (Fri, 22 May 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1252");
  script_bugtraq_id(35017);
  script_name("NTP 'ntpd' Autokey Stack Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_ntp_detect_lin.nasl");
  script_mandatory_keys("NTP/Linux/Ver");

  script_xref(name:"URL", value:"https://launchpad.net/bugs/cve/2009-1252");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1040.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=499694");

  script_tag(name:"affected", value:"NTP version prior to 4.2.4p7

  NTP version 4.2.5 to 4.2.5p73.");
  script_tag(name:"insight", value:"This flaw is due to configuration error in ntp daemon's NTPv4
  authentication code. If ntp daemon is configured to use Public Key Cryptography for NTP Packet
  authentication which lets the attacker send crafted NTP requests.");
  script_tag(name:"solution", value:"Apply the security update according to the OS version.");
  script_tag(name:"summary", value:"This host is running NTP Daemon and is prone to stack overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft a specially malicious
  NTP request packet which can crash ntp daemon or can cause arbitrary code
  execution in the affected machine with local user's privilege.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");

ntpPort = 123;
if( ! get_udp_port_state( ntpPort ) ) exit( 0 );

fullVer = get_kb_item( "NTP/Linux/FullVer" );
if( fullVer && fullVer == "ntpd 4.2.4p4@1.1520-o Sun Nov 22 17:34:54 UTC 2009 (1)" ) exit( 0 ); # debian backport

ntpVer = get_kb_item( "NTP/Linux/Ver" );
if( ntpVer == NULL ) exit( 0 );

if( ( revcomp( a:ntpVer, b:"4.2.4p7" ) < 0 ) ||
    ( ( revcomp( a:ntpVer, b:"4.2.5" ) >= 0 ) && ( revcomp( a:ntpVer, b:"4.2.5p73" ) <= 0 ) ) ||
    ( revcomp( a:ntpVer, b:"4.2.4p7.RC2" ) == 0 ) ) {
  report = report_fixed_ver( installed_version:ntpVer, fixed_version:"4.2.4p7/4.2.5p74" );
  security_message( port:ntpPort, proto:"udp", data:report );
  exit( 0 );
}

exit( 99 );