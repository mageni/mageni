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
  script_oid("1.3.6.1.4.1.25623.1.0.107830");
  script_version("2020-05-28T11:06:20+0000");
  script_tag(name:"last_modification", value:"2020-06-02 09:39:52 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: CPU Vulnerabilities 'Meltdown' and 'Spectre' (huawei-sa-20180606-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Multiple Huawei devices are prone to two groups of CPU vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Security researchers disclosed two groups of CPU vulnerabilities 'Meltdown' and 'Spectre'.");

  script_tag(name:"impact", value:"In some circumstances, a local attacker could exploit these vulnerabilities to 
  read memory information belonging to other processes or other operating system kernels.");

  script_tag(name:"affected", value:"Huawei 1288H V5, 2288H V5, 2488 V5, 2488H V5, 5288 V3, AR100, AR100-S, AR110-S, 
  AR120, AR120-S, AR1220C, AR1500, AR151-S2, AR160 (Exclude AR160F), AR160-S (Exclude AR160F-S), AR2204-XGE, AR3600, 
  SRG1300 and SRG1320E.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180106-01-cpu-en");
  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list( "cpe:/o:huawei:ar100_firmware",
                      "cpe:/o:huawei:ar100-s_firmware",
                      "cpe:/o:huawei:ar110-s_firmware",
                      "cpe:/o:huawei:ar120_firmware",
                      "cpe:/o:huawei:ar120-s_firmware",
                      "cpe:/o:huawei:ar151-s2_firmware",
                      "cpe:/o:huawei:ar160_firmware",
                      "cpe:/o:huawei:ar160-s_firmware",
                      "cpe:/o:huawei:ar1220c_firmware",
                      "cpe:/o:huawei:ar1500_firmware",
                      "cpe:/o:huawei:ar2204-xge_firmware",
                      "cpe:/o:huawei:ar3600_firmware",
                      "cpe:/o:huawei:srg1300_firmware",
                      "cpe:/o:huawei:srg1320e_firmware" );

if( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
version = toupper( infos["version"] );

patch = get_kb_item( "huawei/vrp/patch" );

if( cpe =~ "^cpe:/o:huawei:ar(10|11|12|16)0-s_firmware" ) {
  if (version_is_less(version:version, test_version: "V200R009C00SPC500")) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC500" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe == "cpe:/o:huawei:ar100_firmware" || cpe == "cpe:/o:huawei:ar120_firmware" ||
    cpe == "cpe:/o:huawei:ar1220c_firmware" || cpe == "cpe:/o:huawei:ar1500_firmware" || 
    cpe == "cpe:/o:huawei:ar151-s2_firmware" || cpe == "cpe:/o:huawei:ar160_firmware" || 
    cpe == "cpe:/o:huawei:ar2204-xge_firmware" || cpe == "cpe:/o:huawei:ar3600_firmware" || 
    cpe == "cpe:/o:huawei:srg1300_firmware" || cpe == "cpe:/o:huawei:srg1320e_firmware" ) { 
  if (version_is_less(version:version, test_version: "V200R009C00SPC500")) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC500" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
