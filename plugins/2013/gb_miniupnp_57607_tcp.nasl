###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_miniupnp_57607_tcp.nasl 6079 2017-05-08 09:03:33Z teissa $
#
# MiniUPnP Multiple Denial of Service Vulnerabilities (TCP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105883");
  script_bugtraq_id(57607, 57608);
  script_cve_id("CVE-2013-0229", "CVE-2013-0230", "CVE-2013-1461", "CVE-2013-1462");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 6079 $");

  script_name("MiniUPnP Multiple Denial of Service Vulnerabilities (TCP)");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57607");

  script_tag(name:"last_modification", value:"$Date: 2017-05-08 11:03:33 +0200 (Mon, 08 May 2017) $");
  script_tag(name:"creation_date", value:"2013-02-06 14:48:10 +0100 (Wed, 06 Feb 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("miniupnp/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"MiniUPnP is prone to multiple denial-of-service vulnerabilities.

  This NVT has been merged back into the NVT 'MiniUPnP Multiple Denial of Service Vulnerabilities'
  (OID: 1.3.6.1.4.1.25623.1.0.103657).");

  script_tag(name:"affected", value:"MiniUPnP versions prior to 1.4 are vulnerable.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to cause denial-of-service
  conditions.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("http_func.inc");
include("version_func.inc");

http_port = get_http_port( default:80 );

banner = get_http_banner( port:http_port );
if( ! banner || "miniupnp" >!< tolower( banner ) ) exit( 0 );

version = eregmatch( pattern:"miniupnpd/([0-9.]+)", string:banner, icase:TRUE );
if(! isnull( version[1] ) ) {
  if(version_is_less( version:version[1], test_version:"1.4" ) ) {
    report = report_fixed_ver( installed_version:version[1], fixed_version:"1.4" );
    security_message( port:http_port, data:report );
    exit( 0 );
  }
}

exit( 99 );
