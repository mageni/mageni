###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_sonicwall_gms_mul_sql_vul.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Dell SonicWALL GMS/Analayzer - Multiple SQL Injection Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107121");
  script_version("$Revision: 11977 $");
  script_bugtraq_id(95155);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-11 10:12:05 +0700 (Wed, 11 Jan 2017)");
  script_name("Dell SonicWALL GMS/Analayzer - Multiple SQL Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dell_sonicwall_gms_detection.nasl");
  script_mandatory_keys("sonicwall/ums/detected");
  script_require_ports("Services/www", 8081);

  script_xref(name:"URL", value:"https://support.sonicwall.com/product-notification/215257?productName=SonicWALL%20GMS");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2016-5388.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95155/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40977/");

  script_tag(name:"summary", value:"This host is installed with Dell SonicWALL GMS/Analayzer and is prone to multiple SQL vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SonicWALL GMS/Analayzer suffers from multiple SQL vulnerabilities because it does not sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"A successful exploit may allow an attacker to compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Dell Sonicwall GMS/Analayzer 8.0 up to 8.1");

  script_tag(name:"solution", value:"Update to version 8.2.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:dell:sonicwall_global_management_system",
                      "cpe:/o:dell:sonicwall_analyzer" );

if( ! version = get_app_version( cpe:cpe_list ) ) exit( 0 );

if( version =~ "^8\." ) {
  if( version_is_less( version:version, test_version:"8.2" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"8.2" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
