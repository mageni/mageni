###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_apic_cisco-sa-20151204-openssl.nasl 14041 2019-03-08 01:52:05Z ckuersteiner $
#
# Cisco Application Policy Infrastructure Controller Multiple Vulnerabilities in OpenSSL
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

CPE = "cpe:/a:cisco:application_policy_infrastructure_controller";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106285");
  script_cve_id("CVE-2015-3193", "CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196", "CVE-2015-1794");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 14041 $");

  script_name("Cisco Application Policy Infrastructure Controller Multiple Vulnerabilities in OpenSSL");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151204-openssl");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"On December 3, 2015, the OpenSSL Project released a security advisory
detailing five vulnerabilities. Cisco Application Policy Infrastructure Controller (APIC) Software incorporate
a version of the OpenSSL package affected by one or more vulnerabilities that could allow an unauthenticated,
remote attacker to cause a denial of service (DoS) condition.");

  script_tag(name:"insight", value:"Multiple OpenSSL vulnerabilities affecting Cisco APIC:

  - A vulnerability in the Montgomery multiplication module of OpenSSL could allow an unauthenticated, remote
attacker to cause the library to produce unexpected and possibly weak cryptographic output (CVE-2015-3193).

  - A vulnerability in OpenSSL could allow an unauthenticated, remote attacker to cause a DoS condition
(CVE-2015-3194).

  - A vulnerability in OpenSSL could allow an unauthenticated, remote attacker to cause a DoS condition
(CVE-2015-3195).

  - A vulnerability in OpenSSL could allow an unauthenticated, remote attacker to cause a DoS condition
(CVE-2015-3196).

  - A vulnerability in the anonymous Diffie-Hellman cipher suite in OpenSSL could allow an unauthenticated,
remote attacker to cause a denial of service (DoS) condition (CVE-2015-1794).");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2019-03-08 02:52:05 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-09-22 10:06:54 +0700 (Thu, 22 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_apic_web_detect.nasl");
  script_mandatory_keys("cisco/application_policy_infrastructure_controller/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
                '1.0(1e)',
                '1.1(1j)' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "1.2(2)" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

