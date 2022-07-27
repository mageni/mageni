# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107826");
  script_version("2020-05-28T11:06:20+0000");
  script_tag(name:"last_modification", value:"2020-06-02 09:39:52 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2017-17305", "CVE-2017-17311", "CVE-2017-17312");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Multiple Vulnerabilities in IPsec IKE of Huawei Firewall Products (huawei-sa-20180411-01-Bleichenbacher)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Huawei Firewall products are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:
  
  - A Bleichenbacher Oracle vulnerability in the IPSEC IKEv1 implementations
    Remote attackers can decrypt IPSEC tunnel ciphertext data by leveraging 
    a Bleichenbacher RSA padding oracle. This enables them to cause a 
    Bleichenbacher oracle attack (CVE-2017-17305)

  - Two denial-of-service vulnerabilities in the IPSEC IKEv1 implementations due to improper 
    handling of the malformed messages. An attacker may sent crafted packets to the affected 
    device to exploit these vulnerabilities (CVE-2017-17311, CVE-2017-17312).");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities can impact 
  IPSec tunnel security and lead to denial of services on affected devices.");

  script_tag(name:"affected", value:"Huawei USG2205BSR, USG2220BSR, USG5120BSR and USG5150BSR.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180813-01-Bleichenbacher-en");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list( "cpe:/o:huawei:usg2205bsr_firmware",
                      "cpe:/o:huawei:usg2220bsr_firmware",
                      "cpe:/o:huawei:usg5120bsr_firmware",
                      "cpe:/o:huawei:usg5150bsr_firmware" ) ;

if( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
version = toupper( infos["version"] );

patch = get_kb_item( "huawei/vrp/patch" );

if( cpe =~ "^cpe:/o:huawei:usg2205bsr_firmware" ) {
  if( version == "V300R001C10SPC600" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V300R001C10SPH702" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe == "cpe:/o:huawei:usg2220bsr_firmware" ) {
  if( version == "V300R001C00" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V300R001C10SPH702" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe == "cpe:/o:huawei:usg51(20|50)bsr_firmware" ) {
  if( version == "V300R001C00" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V300R001C10SPH702" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
