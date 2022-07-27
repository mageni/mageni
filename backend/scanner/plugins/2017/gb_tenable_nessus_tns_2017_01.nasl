###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tenable_nessus_tns_2017_01.nasl 12083 2018-10-25 09:48:10Z cfischer $
#
# Tenable Nessus < 6.9.3 Stored Cross-Site Scripting Vulnerabilities
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/a:tenable:nessus';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108040");
  script_version("$Revision: 12083 $");
  script_cve_id("CVE-2017-5179", "CVE-2017-2122");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 11:48:10 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-06 13:00:00 +0100 (Fri, 06 Jan 2017)");
  script_name("Tenable Nessus < 6.9.3 Stored Cross-Site Scripting Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");
  script_require_ports("Services/www", 8834);

  script_tag(name:"summary", value:"This host is installed with Nessus and is prone to
  two stored Cross-Site Scripting Vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Tenable Nessus versions 6.8.0, 6.8.1, 6.9.0, 6.9.1 and 6.9.2.");

  script_tag(name:"solution", value:"Upgrade Tenable Nessus to 6.9.3.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2017-01");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN87760109/index.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.tenable.com/products/nessus");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"6.8.0", test_version2:"6.9.2" ) ) {
   report = report_fixed_ver( installed_version:vers, fixed_version:"6.9.3" );
   security_message( port:port, data:report );
   exit( 0 );
}

exit( 99 );
