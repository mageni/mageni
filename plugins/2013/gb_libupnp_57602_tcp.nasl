###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libupnp_57602_tcp.nasl 6093 2017-05-10 09:03:18Z teissa $
#
# libupnp Multiple Buffer Overflow Vulnerabilities (TCP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105882");
  script_bugtraq_id(57602);
  script_cve_id("CVE-2012-5958", "CVE-2012-5959", "CVE-2012-5960",
                "CVE-2012-5961", "CVE-2012-5962", "CVE-2012-5963",
                "CVE-2012-5964", "CVE-2012-5965");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 6093 $");
  script_name("libupnp Multiple Buffer Overflow Vulnerabilities (TCP)");
  script_tag(name:"last_modification", value:"$Date: 2017-05-10 11:03:18 +0200 (Wed, 10 May 2017) $");
  script_tag(name:"creation_date", value:"2013-02-06 15:35:24 +0100 (Wed, 06 Feb 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("sdk_for_upnp/banner");
  script_require_ports("Services/www", 49152);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57602");

  script_tag(name:"solution", value:"libupnp is prone to multiple buffer-overflow vulnerabilities because
  it fails to perform adequate boundary checks on user-supplied data.");
  script_tag(name:"summary", value:"Updates are available. Please see the references for more information.

  This NVT has been merged back into the NVT 'libupnp Multiple Buffer Overflow Vulnerabilities'
  (OID: 1.3.6.1.4.1.25623.1.0.103658.");
  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code in the
  context of the device that uses the affected library. Failed exploit
  attempts will likely crash the application.");
  script_tag(name:"affected", value:"libupnp versions prior to 1.6.18 are affected.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("http_func.inc");
include("version_func.inc");

http_port = get_http_port( default:49152 );

banner = get_http_banner( port:http_port );
if( ! banner || "sdk for upnp" >!< tolower( banner ) ) exit( 0 );

version = eregmatch( pattern:"(Portable|Intel|WindRiver) SDK for UPnP devices/([0-9.]+)", string:banner, icase:TRUE );
if( ! isnull( version[2] ) ) {
  if( version_is_less( version:version[2], test_version:"1.6.18" ) ) {
    report = report_fixed_ver( installed_version:version[2], fixed_version:"1.6.18" );
    security_message( port:http_port, data:report );
    exit( 0 );
  }
}

exit( 99 );
