# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later # See https://spdx.org/licenses/
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
  script_oid("1.3.6.1.4.1.25623.1.0.107845");
  script_version("2020-06-30T10:29:29+0000");
  script_tag(name:"last_modification", value:"2020-07-01 11:20:27 +0000 (Wed, 01 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-06-25 22:42:17 +0200 (Thu, 25 Jun 2020)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-1810");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Weak Algorithm Vulnerability in Some Huawei Products (huawei-sa-20200108-01-rsa)");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a weak algorithm vulnerability in some Huawei products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The affected products use the RSA algorithm in the SSL key exchange algorithm
  which have been considered as a weak algorithm. Attackers may exploit this vulnerability to leak some information.
  (Vulnerability ID: HWPSIRT-2019-04082)");

  script_tag(name:"impact", value:"Attackers may exploit this vulnerability to leak some information.");

  script_tag(name:"affected", value:"CloudEngine 12800 versions V100R003C00SPC600 V100R003C10SPC100 V100R005C00SPC200 V100R005C00SPC300 V100R005C10HP0001 V100R005C10SPC100 V100R005C10SPC200 V100R006C00 V200R001C00 V200R002C01 V200R002C10 V200R002C20 V200R005C10

  S5700 versions V200R005C00SPC500 V200R005C03 V200R006C00SPC100 V200R006C00SPC300 V200R006C00SPC500 V200R007C00SPC100 V200R007C00SPC500

  S6700 versions V200R005C00SPC500 V200R005C01

  Secospace AntiDDoS8000 versions V500R001C20SPC200 V500R001C20SPC300 V500R001C20SPC500 V500R001C20SPC600 V500R001C60SPC100 V500R001C60SPC101 V500R001C60SPC200 V500R001C60SPC300 V500R001C60SPC500 V500R001C60SPC600 V500R005C00SPC100 V500R005C00SPC200

  Secospace USG6600 versions V500R001C30SPC100.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200108-01-rsa-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:huawei:cloudengine_12800_firmware",
                      "cpe:/o:huawei:s5700_firmware",
                      "cpe:/o:huawei:s6700_firmware",
                      "cpe:/o:huawei:secospace_antiddos8000_firmware",
                      "cpe:/o:huawei:usg6600_firmware" );

if( ! infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
version = toupper( infos["version"] );

patch = get_kb_item( "huawei/vrp/patch" );

if( cpe == "cpe:/o:huawei:cloudengine_12800_firmware" ) {
  if( version == "V100R003C00SPC600" || version == "V100R003C10SPC100" || version == "V100R005C00SPC200" ||
      version == "V100R005C00SPC300" || version == "V100R005C10HP0001" || version == "V100R005C10SPC100" ||
      version == "V100R005C10SPC200" || version == "V100R006C00" || version == "V200R001C00" ||
      version == "V200R002C01" || version == "V200R002C10" || version == "V200R002C20" || version == "V200R005C10") {
    if( ! patch || version_is_less( version: patch, test_version: "V200R019C00SPC800" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R019C00SPC800" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:s5700_firmware" ) {
  if( version == "V200R005C00SPC500" || version == "V200R005C03" || version == "V200R006C00SPC100" ||
      version == "V200R006C00SPC300" || version == "V200R006C00SPC500" || version == "V200R007C00SPC100" ||
      version == "V200R007C00SPC500") {
    if( ! patch || version_is_less( version: patch, test_version: "V200R008C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R008C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:s6700_firmware" ) {
  if( version == "V200R005C00SPC500" || version == "V200R005C01" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R008C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R008C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:secospace_antiddos8000_firmware" ) {
  if( version == "V500R001C20SPC200" || version == "V500R001C20SPC300" || version == "V500R001C20SPC500" ||
      version == "V500R001C20SPC600" || version == "V500R001C60SPC100" || version == "V500R001C60SPC101" ||
      version == "V500R001C60SPC200" || version == "V500R001C60SPC300" || version == "V500R001C60SPC500" ||
      version == "V500R001C60SPC600" || version == "V500R005C00SPC100" || version == "V500R005C00SPC200") {
    if( ! patch || version_is_less( version: patch, test_version: "V500R005C20SPC300" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC300" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:usg6600_firmware" ) {
  if( version == "V500R001C30SPC100" ) {
    if( ! patch || version_is_less(version: patch, test_version: "V500R005C00SPC200" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC200" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

exit( 99 );
