###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ipswitch_imail_server_starttls_cmd_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Ipswitch IMail Server STARTTLS Plaintext Command Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:ipswitch:imail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901195");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_cve_id("CVE-2011-1430");
  script_bugtraq_id(46767);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ipswitch IMail Server STARTTLS Plaintext Command Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("SMTP problems");
  script_dependencies("gb_ipswitch_imail_server_detect.nasl");
  script_mandatory_keys("Ipswitch/IMail/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43676");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/060");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  commands in the context of the user running the application.");
  script_tag(name:"affected", value:"Ipswitch IMail versions 11.03 and Prior.");
  script_tag(name:"insight", value:"This flaw is caused by an error within the 'STARTTLS'
  implementation where the switch from plaintext to TLS is implemented below the
  application's I/O buffering layer, which could allow attackers to inject
  commands during the  plaintext phase of the protocol via man-in-the-middle
  attacks.");
  script_tag(name:"solution", value:"Upgrade to Ipswitch IMail version 11.5 or later.");
  script_tag(name:"summary", value:"The host is running Ipswitch IMail Server and is prone to
  plaintext command injection vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.imailserver.com/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit(0);

if( version_is_less_equal( version:version, test_version:"11.03" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.5" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
