###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libupnp_heap_bo_vuln.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# libupnp Heap Buffer Overflow Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:libupnp_project:libupnp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106377");
  script_version("$Revision: 12051 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-04 14:37:33 +0700 (Fri, 04 Nov 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2016-8863");
  script_name("libupnp Heap Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_libupnp_detect.nasl");
  script_mandatory_keys("libupnp/installed");

  script_xref(name:"URL", value:"https://sourceforge.net/p/pupnp/bugs/133/");
  script_xref(name:"URL", value:"http://pupnp.sourceforge.net/ChangeLog");

  script_tag(name:"summary", value:"libupnp is prone to a heap buffer overflow vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a heap buffer overflow vulnerability in the create_url_list
  function in upnp/src/gena/gena_device.c.");

  script_tag(name:"impact", value:"An unauthenticated attacker may conduct a denial of service attack.");

  script_tag(name:"solution", value:"Upgrade to version 1.6.21 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_in_range( version:version, test_version:"1.6", test_version2:"1.6.20" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.6.21" );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
