###############################################################################
# OpenVAS Vulnerability Test
# $Id: visionsoft-audit-detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Visionsoft Audit multiple vulnerability detection
#
# Authors:
# Tim Brown <timb@openvas.org>
#
# Copyright:
# Copyright (c) 2009 Tim Brown and Portcullis Computer Security Ltd
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.100951");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-07-10 19:42:14 +0200 (Fri, 10 Jul 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-4148", "CVE-2007-4149", "CVE-2007-4150", "CVE-2007-4151", "CVE-2007-4152");
  script_name("Visionsoft Audit multiple vulnerability detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("(c) Tim Brown, 2009");
  script_dependencies("find_service.nasl");
  script_require_ports(5957);

  script_xref(name:"URL", value:"http://www.portcullis-security.com/197.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/198.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/199.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/203.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/204.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/205.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/206.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/207.php");

  script_tag(name:"solution", value:"We recommend that Visionsoft are contacted for a patch.");

  script_tag(name:"summary", value:"Visionsoft Audit multiple vulnerability detection

  The Visionsoft Audit on Demand service may be vulnerable to multiple issues which can be exploited remotely without authentication:
  Heap overflow via LOG command (CVE-2007-4148)
  Multiple arbitrary file overwrites via LOG and SETTINGSFILE command (CVE-2007-4149)
  Denial of service via UNINSTALL command (CVE-2007-4149)

  Additionally, the underlying protocol for authentication has been reported as being vulnerable to replay attacks (CVE-2007-4152) and the settings file is typically installed with inappropriate permissions (CVE-2007-4150).

  On the following platforms, we recommend you mitigate in the described manner:
  Visionsoft Audit 12.4.0.0

  We recommend you mitigate in the following manner:
  Filter inbound traffic to 5957/tcp to only known management hosts");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = 5957;
if( ! get_port_state( port ) ) exit( 0 );
if( known_service( port:port ) ) exit( 0 );
socket = open_sock_tcp( port );
if( ! socket ) exit( 0 );

banner = recv_line( socket:socket, length:1024 );

if( "Visionsoft Audit on Demand Service" >< banner ) {

  register_service( port:port, proto:"visionsoft-audit" );
  banner = recv_line( socket:socket, length:1024 );
  close( socket );

  if( "Version: 12.4.0.0" >< banner ) {
    security_message( port:port, data:"Visionsoft Audit on Demand service seems to be running on this port and appears to be the known vulnerable version: " + banner );
    exit( 0 );
  } else {
    log_message( port:port, data:"Visionsoft Audit on Demand service seems to be running on this port: " + banner );
    exit( 99 );
  }
}

close( socket );
exit( 99 );