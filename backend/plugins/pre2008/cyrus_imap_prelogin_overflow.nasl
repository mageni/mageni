###############################################################################
# OpenVAS Vulnerability Test
# $Id: cyrus_imap_prelogin_overflow.nasl 11272 2018-09-07 02:40:14Z ckuersteiner $
#
# Cyrus IMAP pre-login buffer overflow
#
# Authors:
# Paul Johnston of Westpoint Ltd <paul@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2002 Paul Johnston, Westpoint Ltd
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

CPE = "cpe:/a:cmu:cyrus_imap_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11196");
  script_version("$Revision: 11272 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 04:40:14 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-1580");
  script_bugtraq_id(6298);
  script_name("Cyrus IMAP pre-login buffer overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Paul Johnston, Westpoint Ltd");
  script_family("Gain a shell remotely");
  script_dependencies("secpod_cyrus_imap_server_detect.nasl");
  script_require_ports("Services/imap", 143, "Services/pop3", 110);
  script_mandatory_keys("Cyrus/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/301864");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6298");

  script_tag(name:"solution", value:"If possible, upgrade to an unaffected version. However, at
  the time of writing no official fix was available. There is a source
  patch against 2.1.10 in the referenced Bugtraq report.");

  script_tag(name:"summary", value:"According to its banner, the remote Cyrus IMAP
  server is vulnerable to a pre-login buffer overrun.");

  script_tag(name:"impact", value:"An attacker without a valid login could exploit this, and would be
  able to execute arbitrary commands as the owner of the Cyrus
  process. This would allow full access to all users' mailboxes.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( egrep( pattern:"^(1\.*|2\.0\.*|2\.1\.[1-9][^0-9]|2\.1\.10)[0-9]*$", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );