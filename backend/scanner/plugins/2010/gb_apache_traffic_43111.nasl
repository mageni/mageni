###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_traffic_43111.nasl 12876 2018-12-21 16:05:36Z cfischer $
#
# Apache Traffic Server Remote DNS Cache Poisoning Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:traffic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100797");
  script_version("$Revision: 12876 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-21 17:05:36 +0100 (Fri, 21 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-09-10 15:25:30 +0200 (Fri, 10 Sep 2010)");
  script_bugtraq_id(43111);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-2952");
  script_name("Apache Traffic Server Remote DNS Cache Poisoning Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_apache_traffic_detect.nasl");
  script_require_ports("Services/http_proxy", 8080, 3128);
  script_mandatory_keys("apache_trafficserver/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43111");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/TS-425");
  script_xref(name:"URL", value:"http://www.nth-dimension.org.uk/pub/NDSA20100830.txt.asc");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to a remote DNS cache-poisoning
  vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to divert data from a legitimate
  site to an attacker-specified site.

  Successful exploits will allow the attacker to manipulate cache data, potentially facilitating
  man-in-the-middle, site-impersonation, or denial-of-service attacks.");

  script_tag(name:"affected", value:"Versions prior to Apache Traffic Server 2.0.1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit(0);

vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"2.0.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );