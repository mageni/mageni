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
  script_oid("1.3.6.1.4.1.25623.1.0.107821");
  script_version("2020-05-28T11:06:20+0000");
  script_tag(name:"last_modification", value:"2020-06-02 09:39:52 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-17302");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Memory Leak Vulnerability (huawei-sa-20180124-01-memory)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Multiple Huawei products are prone to a memory leak vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a memory leak vulnerability in some Huawei products.");

  script_tag(name:"impact", value:"An authenticated, local attacker may craft and load some specific Certificate
  Revocation List(CRL) configuration files to the devices repeatedly. Due to not releasing allocated memory properly,
  successful exploitation may result in memory leak and abnormal services behaviour.");

  script_tag(name:"affected", value:"Huawei DP300, RP200, TE30, TE40, TE50 and TE60.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180124-01-memory-en");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list( "cpe:/o:huawei:dp300_firmware",
                      "cpe:/o:huawei:rp200_firmware",
                      "cpe:/o:huawei:te30_firmware",
                      "cpe:/o:huawei:te40_firmware",
                      "cpe:/o:huawei:te50_firmware",
                      "cpe:/o:huawei:te60_firmware" ) ;

if( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
version = toupper( infos["version"] );

patch = get_kb_item( "huawei/vrp/patch" );

if( cpe =~ "^cpe:/o:huawei:te(3|4|5|6)0_firmware" ) {
  if( version == "V100R001C10" || version == "V500R002C00" || version == "V600R006C00" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V600R006C00SPC500" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe == "cpe:/o:huawei:dp300_firmware" ) {
  if( version == "V500R002C00" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V500R002C00SPCb00" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( cpe == "cpe:/o:huawei:rp200_firmware" ) {
  if( version == "V600R006C00" ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"V600R006C00SPC500" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
