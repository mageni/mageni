###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_puppet_enterprise_dos_vuln.nasl 13864 2019-02-26 07:19:57Z cfischer $
#
# Puppet Enterprise 2017 < 2017.2.2 Denial of Service Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113101");
  script_version("$Revision: 13864 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 08:19:57 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-02-02 11:40:38 +0100 (Fri, 02 Feb 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-2296");

  script_name("Puppet Enterprise 2017 < 2017.2.2 Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_puppet_enterprise_detect.nasl");
  script_mandatory_keys("puppet_enterprise/installed");

  script_tag(name:"summary", value:"Puppet Enterprise before 2017.2.2 is prone to a Denial of Service Vulnerability.

  This NVT has duplicated the existing NVT 'Puppet Enterprise 2017 < 2017.2.2 DoS Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.106930).");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"In the affected versions, using specially formatted strings with certain formatting characters as Classifier node group names or RBAC role display names causes errors, effectively causing a DoS to the service.");
  script_tag(name:"affected", value:"Puppet Enterprise from 2017.1.0 through 2017.2.1");
  script_tag(name:"solution", value:"Update to 2017.2.2");

  script_xref(name:"URL", value:"https://puppet.com/security/cve/cve-2017-2296");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

CPE = "cpe:/a:puppet:enterprise";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( port: port, cpe: CPE ) ) exit( 0 );

if( version_in_range( version: version, test_version: "2017.1.0", test_version2: "2017.2.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2017.2.2" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
