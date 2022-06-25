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
  script_oid("1.3.6.1.4.1.25623.1.0.107823");
  script_version("2020-05-28T11:06:20+0000");
  script_tag(name:"last_modification", value:"2020-06-02 09:39:52 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-17286", "CVE-2017-17287");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Two Buffer Overflow Vulnerabilities (huawei-sa-20180207-01-encryption)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Due to insufficient input validation, these vulnerabilities exist in some 
  Huawei products:
  
  - An out-of-bounds write vulnerability (CVE-2017-17286)
  
  - An out-of-bounds read vulnerability (CVE-2017-17287).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote, unauthenticated attacker may craft encryption keys and/or send crafted 
  signatures to the affected products");

  script_tag(name:"impact", value:"Successful exploitation may cause buffer overflows and abnormal services behaviour.");

  script_tag(name:"affected", value:"Huawei AR120-S, AR1200, AR1200-S, AR150, AR150-S, AR160, AR200, AR200-S,
  AR2200, AR2200-S, AR3200, AR510, NetEngine16EX, SRG1300, SRG2300 and SRG3300.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180207-01-encryption-en");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list( "cpe:/o:huawei:ar120-s_firmware",
                      "cpe:/o:huawei:ar150_firmware",
                      "cpe:/o:huawei:ar150-s_firmware",
                      "cpe:/o:huawei:ar160_firmware",
                      "cpe:/o:huawei:ar200_firmware",
                      "cpe:/o:huawei:ar200-s_firmware",
                      "cpe:/o:huawei:ar1200_firmware",
                      "cpe:/o:huawei:ar1200-s_firmware",
                      "cpe:/o:huawei:ar2200_firmware",
                      "cpe:/o:huawei:ar2200-s_firmware",
                      "cpe:/o:huawei:ar3200_firmware",
                      "cpe:/o:huawei:ar3600_firmware",
                      "cpe:/o:huawei:ar510_firmware",
                      "cpe:/o:huawei:netengine16ex_firmware",
                      "cpe:/o:huawei:srg1300_firmware",
                      "cpe:/o:huawei:srg2300_firmware",
                      "cpe:/o:huawei:srg3300_firmware" );

if( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
version = toupper( infos["version"] );

patch = get_kb_item( "huawei/vrp/patch" );

if( cpe =~ "^cpe:/o:huawei:ar(12|15|120|20|220)0-s_firmware" ) {
  if( version == "V200R005C32" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" ||
      version == "V200R008C30" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC300" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe == "cpe:/o:huawei:ar1200_firmware" ) {
  if( version == "V200R005C32" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" ||
      version == "V200R007C02" || version == "V200R008C20" || version == "V200R008C30" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC300" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe == "cpe:/o:huawei:ar150_firmware" ) {
  if( version == "V200R005C32" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" ||
      version == "V200R007C02" || version == "V200R008C20" || version == "V200R008C30" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC300" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe == "cpe:/o:huawei:ar160_firmware" ) {
  if( version == "V200R005C32" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" ||
      version == "V200R007C02" || version == "V200R008C20" || version == "V200R008C30" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC300" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe == "cpe:/o:huawei:ar200_firmware" ) {
  if( version == "V200R005C32" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" ||
      version == "V200R008C20" || version == "V200R008C30" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC300" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe == "cpe:/o:huawei:ar2200_firmware" ) {
  if( version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" || version == "V200R007C02" ||
      version == "V200R008C20" || version == "V200R008C30" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC300" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe == "cpe:/o:huawei:ar3200_firmware" ) {
  if( version == "V200R005C32" || version == "V200R006C10" || version == "V200R006C11" || version == "V200R007C00" ||
      version == "V200R007C01" || version == "V200R007C02" || version == "V200R008C00" || version == "V200R008C10" ||
      version == "V200R008C20" || version == "V200R008C30" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC300" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe == "cpe:/o:huawei:ar3600_firmware" ) {
  if( version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" || version == "V200R008C20" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC300" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe == "cpe:/o:huawei:ar510_firmware" ) {
  if( version == "V200R005C32" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" ||
      version == "V200R008C30" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC300" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe =~ "^cpe:/o:huawei:netengine16ex_firmware" ) {
  if( version == "V200R005C32" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" ||
      version == "V200R008C30" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC300" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe =~ "^cpe:/o:huawei:srg[123]300_firmware" ) {
  if( version == "V200R005C32" || version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C02" ||
      version == "V200R008C20" || version == "V200R008C30" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V200R009C00SPC300" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
