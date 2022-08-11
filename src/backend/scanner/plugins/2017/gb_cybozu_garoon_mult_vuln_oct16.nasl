###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cybozu_garoon_mult_vuln_oct16.nasl 11919 2018-10-16 09:49:19Z mmartin $
#
# Cybozu Garoon Multiple Vulnerabilities - Oct16
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:cybozu:garoon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108176");
  script_version("$Revision: 11919 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 11:49:19 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-12 07:54:29 +0200 (Mon, 12 Jun 2017)");
  script_cve_id("CVE-2016-4906", "CVE-2016-4907", "CVE-2016-4908", "CVE-2016-4909",
                "CVE-2016-4910", "CVE-2016-7801", "CVE-2016-7802", "CVE-2016-7803");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Cybozu Garoon Multiple Vulnerabilities - Oct16");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_cybozu_products_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("CybozuGaroon/Installed");

  script_tag(name:"summary", value:"This host is installed with Cybozu Garoon
  and is vulnerable to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cybozu Garoon is prone to multiple vulnerabilities");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to do redirection, XSS, authentication bypass, SQL Injection and denial of services attacks.");

  script_tag(name:"affected", value:"Cybozu Garoon 3.0.0 to 4.2.2.");

  script_tag(name:"solution", value:"Update to Cybozu Garoon 4.2.3 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers,  test_version:"3.0.0", test_version2:"4.2.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.2.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit ( 99 );
