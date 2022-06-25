###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xr_cisco-sa-20160916-ikev1.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Cisco IOS XR Software IKEv1 Information Disclosure Vulnerability
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

CPE = "cpe:/o:cisco:ios_xr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106261");
  script_cve_id("CVE-2016-6415");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 12431 $");

  script_name("Cisco IOS XR Software IKEv1 Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160916-ikev1");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb29204");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb36055");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates, please see the referenced vendor advisory for more information on the fixed versions.");

  script_tag(name:"summary", value:"A vulnerability in IKEv1 packet processing code in Cisco IOS Software
could allow an unauthenticated, remote attacker to retrieve memory contents, which could lead to the
disclosure of confidential information.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient condition checks in the part of
the code that handles IKEv1 security negotiation requests. An attacker could exploit this vulnerability by
sending a crafted IKEv1 packet to an affected device configured to accept IKEv1 security negotiation requests.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to retrieve memory contents,
which could lead to the disclosure of confidential information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-19 09:23:33 +0700 (Mon, 19 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xr_version.nasl");
  script_mandatory_keys("cisco/ios_xr/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

affected = make_list(
		'4.3.4',
		'5.2.1',
		'5.2.2',
		'5.2.3',
		'5.2.4',
		'5.2.5',
		'5.2.6' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver( installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit(99);
