###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aerospike_database_server_95415.nasl 13999 2019-03-05 13:15:01Z cfischer $
#
# Aerospike Database Server Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:aerospike:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140132");
  script_bugtraq_id(95415, 95419, 95421);
  script_cve_id("CVE-2016-9050", "CVE-2016-9054", "CVE-2016-9052", "CVE-2016-9049", "CVE-2016-9051", "CVE-2016-9053");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 13999 $");

  script_name("Aerospike Database Server Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95415");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95419");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95421");
  script_xref(name:"URL", value:"http://www.aerospike.com/");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0264/");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0263/");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0265/");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0267/");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Ask the vendor for an update.");

  script_tag(name:"summary", value:"Aerospike Database Server is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"- CVE-2016-9049

  An exploitable denial-of-service vulnerability exists in the fabric-worker component of Aerospike Database
  Server. A specially crafted packet can cause the server process to dereference a null pointer. An attacker can
  simmply connect to a TCP port in order to trigger this vulnerability.

  - CVE-2016-9050

  Aerospike Database Server is prone to a information-disclosure vulnerability.
  Attackers can exploit this issue to obtain sensitive information that may aid in further attacks.

  - CVE-2016-9051

  An exploitable out-of-bounds write vulnerability exists in the batch transaction field parsing functionality
  of Aerospike Database Server. A specially crafted packet can cause an out-of-bounds write resulting in memory
  corruption which can lead to remote code execution. An attacker can simply connect to the port to trigger this
  vulnerability.

  - CVE-2016-9052

  Aerospike Database Server is prone to a stack-based buffer-overflow vulnerability.
  Attackers can exploit this issue to execute arbitrary code in the context of the affected application.
  Failed exploit attempts will likely cause a denial-of-service condition.

  - CVE-2016-9053

  An exploitable out-of-bounds indexing vulnerability exists within the RW fabric message particle type of
  Aerospike Database Server. A specially crafted packet can cause the server to fetch a function table outside
  the bounds of an array resulting in remote code execution. An attacker can simply connect to the port to
  trigger this vulnerability.

  - CVE-2016-9054

  Aerospike Database Server is prone to a stack-based buffer-overflow vulnerability.
  Attackers can exploit this issue to execute arbitrary code in the context of the affected application.
  Failed exploit attempts will likely cause a denial-of-service condition.");

  script_tag(name:"affected", value:"Aerospike Database Server versions up to 3.10.0.3 are known to be affected.
  Other versions might be affected as well.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 14:15:01 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-01-27 14:35:35 +0100 (Fri, 27 Jan 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_aerospike_xdr_detect.nasl", "gb_aerospike_telnet_detect.nasl");
  script_mandatory_keys("aerospike/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

# Advisory says "Tested Versions" "Aerospike Database Server 3.10.0.3". So it's not clear if other version are affected as well. To be sure check for <= 3.10.0.3
if( version_is_less_equal( version: version, test_version: "3.10.0.3" ) )
{
    report = report_fixed_ver( installed_version:version, fixed_version:"Ask vendor");
    security_message( port:0, data:report );
    exit (0 );
}

exit( 99 );