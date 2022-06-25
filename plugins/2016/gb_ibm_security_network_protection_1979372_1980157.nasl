###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_security_network_protection_1979372_1980157.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# IBM Security Network Protection Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:security_network_protection";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105747");
  script_version("$Revision: 11961 $");
  script_name("IBM Security Network Protection Multiple Vulnerabilities");
  script_cve_id("CVE-2016-0787", "CVE-2015-8629", "CVE-2015-8631");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21980157");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21979372");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"MIT Kerberos could allow a remote authenticated attacker to obtain sensitive information, caused by a null termination in the xdr_nullstring() function. By sending specially-crafted data, an attacker could exploit this vulnerability to obtain sensitive information from the memory.

libssh2 could provide weaker than expected security, caused by a type confusion error during the SSHv2 handshake resulting in the generation of a reduced amount of random bits for Diffie-Hellman. An attacker could exploit this vulnerability using the truncated Diffie-Hellman secret to launch further attacks on the system.");
  script_tag(name:"solution", value:"Update to 5.3.1.9/5.3.2.3 or newer");
  script_tag(name:"summary", value:"IBM Security Network Protection is prone to multiple vulnerabilities.

1. IBM Security Network Protection uses Kerberos (krb5) to provide network authentication. The Kerberos (krb5) version that is shipped with IBM Security Network Protection contains multiple security vulnerabilities.
2. The libssh2 packages provide a library that implements the SSHv2 protocol. A security vulnerability has been discovered in libssh2 used with IBM Security Network Protection.");
  script_tag(name:"affected", value:"IBM Security Network Protection 5.3.1
IBM Security Network Protection 5.3.2");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-01 15:30:38 +0200 (Wed, 01 Jun 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_security_network_protection_version.nasl");
  script_mandatory_keys("isnp/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version =~ "^5\.3\.1" )
  if( version_is_less( version:version, test_version:"5.3.1.9" ) ) fix = "5.3.1.9";

if( version =~ "^5\.3\.2" )
  if( version_is_less( version:version, test_version:"5.3.2.3" ) ) fix = "5.3.2.3";

if( fix )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

