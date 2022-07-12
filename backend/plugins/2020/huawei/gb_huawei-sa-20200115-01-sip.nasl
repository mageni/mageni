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
  script_oid("1.3.6.1.4.1.25623.1.0.107846");
  script_version("2020-06-29T14:46:52+0000");
  script_tag(name:"last_modification", value:"2020-07-01 11:20:27 +0000 (Wed, 01 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-06-25 22:42:17 +0200 (Thu, 25 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2019-19415", "CVE-2019-19416", "CVE-2019-19417");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Three DoS Vulnerabilities in the SIP Module of Some Huawei Products (huawei-sa-20200115-01-sip)");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There are three denial of service (DoS) vulnerabilities in the SIP module of some Huawei products.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote attacker could exploit these three vulnerabilities by sending a specially crafted messages
  to the affected device. Due to the insufficient verification of the packets, successful exploit could allow the attacker to cause buffer
  overflow and dead loop, leading to DoS condition. (Vulnerability ID: HWPSIRT-2017-03027, HWPSIRT-2017-03028 and HWPSIRT-2017-03029)");

  script_tag(name:"impact", value:"Successful exploit of this vulnerability could lead to a DoS condition.");

  script_tag(name:"affected", value:"AR120-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

  AR1200 versions V200R006C10 V200R006C13 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

  AR1200-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

  AR150 versions V200R006C10 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

  AR150-S versions V200R006C10SPC300 V200R007C00 V200R008C20 V200R008C30

  AR160 versions V200R006C10 V200R006C12 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

  AR200 versions V200R006C10 V200R007C00 V200R007C01 V200R008C20 V200R008C30

  AR200-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

  AR2200 versions V200R006C10 V200R006C13 V200R006C16PWE V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

  AR2200-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

  AR3200 versions V200R006C10 V200R006C11 V200R007C00 V200R007C01 V200R007C02 V200R008C00 V200R008C10 V200R008C20 V200R008C30

  AR3600 versions V200R006C10 V200R007C00 V200R007C01 V200R008C20

  AR510 versions V200R006C10 V200R006C12 V200R006C13 V200R006C15 V200R006C16 V200R006C17 V200R007C00SPC180T V200R007C00SPC600 V200R007C00SPC900 V200R007C00SPCb00 V200R008C20 V200R008C30

  DP300 versions V500R002C00

  IPS Module versions V100R001C10 V100R001C20 V100R001C30 V500R001C00 V500R001C20 V500R001C30 V500R001C50

  NGFW Module versions V100R001C10 V100R001C20 V100R001C30 V500R001C00 V500R001C20 V500R002C00 V500R002C10

  NIP6300 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50

  NIP6600 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50

  NIP6800 versions V500R001C30 V500R001C50

  NetEngine16EX versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

  RSE6500 versions V500R002C00

  SMC2.0 versions V100R003C00SPC200T V100R003C00SPC300T V100R003C00SPC301T V100R003C10 V100R005C00SPC100 V100R005C00SPC101B001T V100R005C00SPC102 V100R005C00SPC103 V100R005C00SPC200 V100R005C00SPC201T V500R002C00 V600R006C00

  SRG1300 versions V200R006C10 V200R007C00 V200R007C02 V200R008C20 V200R008C30

  SRG2300 versions V200R006C10 V200R007C00 V200R007C02 V200R008C20 V200R008C30

  SRG3300 versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

  SVN5600 versions V200R003C00 V200R003C10

  SVN5800 versions V200R003C00 V200R003C10

  SVN5800-C versions V200R003C00 V200R003C10

  SeMG9811 versions V300R001C01SPC500 V300R001C01SPC500T V300R001C01SPC700 V300R001C01SPCa00

  Secospace USG6300 versions V100R001C10 V100R001C20 V100R001C30 V500R001C00 V500R001C20 V500R001C30 V500R001C50

  Secospace USG6500 versions V100R001C10 V100R001C20 V100R001C30 V500R001C00 V500R001C20 V500R001C30 V500R001C50

  Secospace USG6600 versions V100R001C00 V100R001C10 V100R001C20 V100R001C30 V500R001C00 V500R001C20 V500R001C30 V500R001C50

  SoftCo versions V200R001C01SPC300 V200R001C01SPC400 V200R001C01SPC500 V200R001C01SPC600 V200R001C01SPH703 V200R003C00SPC100 V200R003C00SPC200 V200R003C00SPC300 V200R003C00SPC500 V200R003C20

  TE30 versions V100R001C02SPC100 V100R001C02SPC200 V100R001C10 V500R002C00SPC200 V500R002C00SPC600 V500R002C00SPC700 V500R002C00SPC900 V500R002C00SPCb00 V600R006C00

  TE40 versions V500R002C00SPC600 V500R002C00SPC700 V500R002C00SPC900 V500R002C00SPCb00 V600R006C00

  TE50 versions V500R002C00SPC600 V500R002C00SPCb00 V600R006C00

  TE60 versions V100R001C01SPC100 V100R001C10 V100R001C10SPC300 V100R001C10SPC400 V100R001C10SPC500 V100R001C10SPC600 V100R001C10SPC800 V100R003C00 V500R002C00 V500R002C00SPC100 V500R002C00SPC200 V500R002C00SPC300 V500R002C00SPC600 V500R002C00SPC700 V500R002C00SPC800 V500R002C00SPC900 V500R002C00SPCa00 V500R002C00SPCb00 V600R006C00 V600R006C00SPC200

  TP3206 versions V100R002C00

  USG9500 versions V300R001C01 V300R001C20 V500R001C00 V500R001C20 V500R001C30 V500R001C50

  USG9520 versions V300R001C01SPC800PWE

  USG9560 versions V300R001C20SPC300

  VP9660 versions V200R001C02SPC100 V200R001C02SPC200 V200R001C02SPC300 V200R001C02SPC300T V200R001C02SPC400 V200R001C30SPC100 V200R001C30SPC100B015T V200R001C30SPC101 V200R001C30SPC101TB015 V200R001C30SPC102T V200R001C30SPC103T V200R001C30SPC104T V200R001C30SPC200 V200R001C30SPC200B022T V200R001C30SPC201B023T V200R001C30SPC202B025T V200R001C30SPC203T V200R001C30SPC206T V200R001C30SPC207T V200R001C30SPC208T V200R001C30SPC209T V200R001C30SPC300 V200R001C30SPC400 V200R001C30SPC400B001 V200R001C30SPC400T V200R001C30SPC401T V200R001C30SPC402T V200R001C30SPC403T V200R001C30SPC404T V200R001C30SPC405T V200R001C30SPC600 V200R001C30SPC700 V200R001C30SPC700T V200R001C30SPC701T V200R001C30SPC702T V200R001C30SPC703T V200R001C30SPC800 V200R001C30SPC800T V200R001C30SPC900 V200R001C30SPCa00 V200R001C30SPCa00T V200R001C30SPCa01 V200R001C30SPCa01T V200R001C30SPCa02T V200R001C30SPCb00 V200R001C30SPCc00 V200R001C30SPCd00 V200R001C30SPCd00T V200R001C30SPCd01T V200R001C30SPCd02T V200R001C30SPCd03T V200R001C30SPCd04T V200R001C30SPCd05T V200R001C30SPCe00 V200R001C30SPCe01T V200R001C30SPCf00 V200R001C30SPCg00 V200R001C30SPCh00 V200R001C30SPCi00 V200R001C30SPCj00 V500R002C00 V500R002C00SPC001T V500R002C00SPC200 V500R002C00SPC200T V500R002C00SPC201T V500R002C00SPC203T V500R002C00SPC204T V500R002C00SPC205T V500R002C00SPC206T V500R002C00SPC300 V500R002C00SPC400 V500R002C00SPC500 V500R002C00SPC600 V500R002C00SPC700 V500R002C00SPC800 V500R002C00SPC900 V500R002C00SPC900T V500R002C00SPC901T V500R002C00SPCa00 V500R002C00SPCb00 V500R002C00SPCb01T V500R002C00SPCc00 V500R002C00SPCd00 V500R002C00T V500R002C10 V500R002C10SPC100 V500R002C10SPC100T V500R002C10T

  ViewPoint 8660 versions V100R008C03B013SP02 V100R008C03B013SP03 V100R008C03B013SP04 V100R008C03SPC100 V100R008C03SPC200 V100R008C03SPC300 V100R008C03SPC400 V100R008C03SPC500 V100R008C03SPC600 V100R008C03SPC700 V100R008C03SPC800 V100R008C03SPC900 V100R008C03SPCa00 V100R008C03SPCb00 V100R008C03SPCc00

  ViewPoint 9030 versions V100R011C02SPC100 V100R011C03B012SP15 V100R011C03B012SP16 V100R011C03B015SP03 V100R011C03LGWL01SPC100 V100R011C03LGWL01SPC100B012 V100R011C03SPC100 V100R011C03SPC200 V100R011C03SPC300 V100R011C03SPC400 V100R011C03SPC500

  eSpace U1910 versions V100R001C20SPC300 V100R001C20SPC400 V100R001C20SPC500 V100R001C20SPC600 V100R001C20SPH703 V200R003C00 V200R003C20 V200R003C30

  eSpace U1911 versions V100R001C20SPC300 V100R001C20SPC400 V100R001C20SPC500 V100R001C20SPC600 V100R001C20SPH309 V100R001C20SPH703 V200R003C00 V200R003C20 V200R003C30

  eSpace U1930 versions V100R001C20SPC300 V100R001C20SPC400 V100R001C20SPC500 V100R001C20SPC600 V100R001C20SPH703 V200R003C00 V200R003C20 V200R003C30

  eSpace U1960 versions V100R001C01SPC500 V100R001C20LCRW01T V100R001C20SPC300 V100R001C20SPC400 V100R001C20SPC600 V100R001C20SPC600T V100R001C20SPH309 V100R001C20SPH703 V200R003C00 V200R003C20 V200R003C30

  eSpace U1980 versions V100R001C01SPC500T V100R001C20SPC300 V100R001C20SPC400 V100R001C20SPC500T V100R001C20SPC502 V100R001C20SPC600 V100R001C20SPH309 V100R001C20SPH703 V200R003C00 V200R003C20 V200R003C30

  eSpace U1981 versions V100R001C20SPC300 V100R001C20SPC400 V100R001C20SPC500 V100R001C20SPC600 V100R001C20SPC700 V100R001C20SPH702 V100R001C20SPH703 V100R001C30 V200R003C00 V200R003C20 V200R003C30.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200115-01-sip-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:huawei:ar120-s_firmware",
                      "cpe:/o:huawei:ar1200_firmware",
                      "cpe:/o:huawei:ar1200-s_firmware",
                      "cpe:/o:huawei:ar150_firmware",
                      "cpe:/o:huawei:ar150-s_firmware",
                      "cpe:/o:huawei:ar160_firmware",
                      "cpe:/o:huawei:ar200_firmware",
                      "cpe:/o:huawei:ar200-s_firmware",
                      "cpe:/o:huawei:ar2200_firmware",
                      "cpe:/o:huawei:ar2200-s_firmware",
                      "cpe:/o:huawei:ar3200_firmware",
                      "cpe:/o:huawei:ar3600_firmware",
                      "cpe:/o:huawei:ar510_firmware",
                      "cpe:/o:huawei:dp300_firmware",
                      "cpe:/o:huawei:ips_module_firmware",
                      "cpe:/o:huawei:ngfw_module_firmware",
                      "cpe:/o:huawei:nip6300_firmware",
                      "cpe:/o:huawei:nip6600_firmware",
                      "cpe:/o:huawei:nip6800_firmware",
                      "cpe:/o:huawei:netengine16ex_firmware",
                      "cpe:/o:huawei:rse6500_firmware",
                      "cpe:/o:huawei:smc2.0_firmware",
                      "cpe:/o:huawei:srg1300_firmware",
                      "cpe:/o:huawei:srg2300_firmware",
                      "cpe:/o:huawei:srg3300_firmware",
                      "cpe:/o:huawei:svn5600_firmware",
                      "cpe:/o:huawei:svn5800_firmware",
                      "cpe:/o:huawei:svn5800-c_firmware",
                      "cpe:/o:huawei:semg9811_firmware",
                      "cpe:/o:huawei:secospace_usg6300_firmware",
                      "cpe:/o:huawei:secospace_usg6500_firmware",
                      "cpe:/o:huawei:secospace_usg6600_firmware",
                      "cpe:/o:huawei:softco_firmware",
                      "cpe:/o:huawei:te30_firmware",
                      "cpe:/o:huawei:te40_firmware",
                      "cpe:/o:huawei:te50_firmware",
                      "cpe:/o:huawei:te60_firmware",
                      "cpe:/o:huawei:tp3206_firmware",
                      "cpe:/o:huawei:usg9500_firmware",
                      "cpe:/o:huawei:usg9520_firmware",
                      "cpe:/o:huawei:usg9560_firmware",
                      "cpe:/o:huawei:vp9660_firmware",
                      "cpe:/o:huawei:viewpoint_8660_firmware",
                      "cpe:/o:huawei:viewpoint_9030_firmware",
                      "cpe:/o:huawei:espace_u1910_firmware",
                      "cpe:/o:huawei:espace_u1911_firmware",
                      "cpe:/o:huawei:espace_u1930_firmware",
                      "cpe:/o:huawei:espace_u1960_firmware",
                      "cpe:/o:huawei:espace_u1980_firmware",
                      "cpe:/o:huawei:espace_u1981_firmware" );

if( ! infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );

if( cpe == "cpe:/o:huawei:ar120-s_firmware" ) {
  if( version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar1200_firmware" ) {
  if( version == "V200R006C10" || version == "V200R006C13" || version == "V200R007C00" || version == "V200R007C01" ||
      version == "V200R007C02" || version == "V200R008C20" || version == "V200R008C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00") ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar1200-s_firmware" ) {
  if( version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C30" ) {
    if( ! patch || version_is_less(version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar150_firmware" ) {
  if( version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" || version == "V200R007C02" ||
      version == "V200R008C20" || version == "V200R008C30") {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar150-s_firmware" ) {
  if( version == "V200R006C10SPC300" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar160_firmware" ) {
  if( version == "V200R006C10" || version == "V200R006C12" || version == "V200R007C00" || version == "V200R007C01" ||
      version == "V200R007C02" || version == "V200R008C20" || version == "V200R008C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar200_firmware" ) {
  if(version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" || version == "V200R008C20" || version == "V200R008C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar200-s_firmware" ) {
  if( version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar2200_firmware" ) {
  if( version == "V200R006C10" || version == "V200R006C13" || version == "V200R006C16PWE" || version == "V200R007C00" ||
      version == "V200R007C01" || version == "V200R007C02" || version == "V200R008C20" || version == "V200R008C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar2200-s_firmware" ) {
  if( version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar3200_firmware" ) {
  if( version == "V200R006C10" || version == "V200R006C11" || version == "V200R007C00" || version == "V200R007C01" ||
      version == "V200R007C02" || version == "V200R008C00" || version == "V200R008C10" || version == "V200R008C20" ||
      version == "V200R008C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar3600_firmware" ) {
  if( version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C01" || version == "V200R008C20") {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00") ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar510_firmware" ) {
  if( version == "V200R006C10" || version == "V200R006C12" || version == "V200R006C13" || version == "V200R006C15" ||
      version == "V200R006C16" || version == "V200R006C17" || version == "V200R007C00SPC180T" || version == "V200R007C00SPC600" ||
      version == "V200R007C00SPC900" || version == "V200R007C00SPCB00" || version == "V200R008C20" || version == "V200R008C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:dp300_firmware" ) {
  if( version == "V500R002C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R002C00SPCb00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPCb00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ips_module_firmware" ) {
  if( version == "V100R001C10" || version == "V100R001C20" || version == "V100R001C30" || version == "V500R001C00" ||
      version == "V500R001C20" || version == "V500R001C30" || version == "V500R001C50" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R001C60SPC500+V500R001SPH015" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC500+V500R001SPH015" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ngfw_module_firmware" ) {
  if( version == "V100R001C10" || version == "V100R001C20" || version == "V100R001C30" || version == "V500R001C00" ||
      version == "V500R001C20" || version == "V500R002C00" || version == "V500R002C10" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R002C20SPC500 + V500R002SPH015" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R002C20SPC500 + V500R002SPH015" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:nip6300_firmware" ) {
  if( version == "V500R001C00" || version == "V500R001C20" || version == "V500R001C30" || version == "V500R001C50" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R002C20SPC500 + V500R002SPH015" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R002C20SPC500 + V500R002SPH015" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:nip6600_firmware" ) {
  if( version == "V500R001C00" || version == "V500R001C20" || version == "V500R001C30" || version == "V500R001C50" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R001C60SPC500 +V500R001SPH015" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC500 + V500R001SPH015" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:nip6800_firmware" ) {
  if( version == "V500R001C30" || version == "V500R001C50" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R001C60SPC500 +V500R001SPH015" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC500 +V500R001SPH015" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:netengine16ex_firmware" ) {
  if( version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:rse6500_firmware" ) {
  if( version == "V500R002C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R002C00SPC800" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPC800" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:smc2.0_firmware" ) {
  if( version == "V100R003C00SPC200T" || version == "V100R003C00SPC300T" || version == "V100R003C00SPC301T" ||
      version == "V100R003C10" || version == "V100R005C00SPC100" || version == "V100R005C00SPC101B001T" ||
      version == "V100R005C00SPC102" || version == "V100R005C00SPC103" || version == "V100R005C00SPC200" ||
      version == "V100R005C00SPC201T" || version == "V500R002C00" || version == "V600R006C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R002C00SPCc00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPCc00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:srg1300_firmware" ) {
  if( version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C02" || version == "V200R008C20" || version == "V200R008C30") {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:srg2300_firmware" ) {
  if( version == "V200R006C10" || version == "V200R007C00" || version == "V200R007C02" || version == "V200R008C20" || version == "V200R008C30") {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:srg3300_firmware" ) {
  if( version == "V200R006C10" || version == "V200R007C00" || version == "V200R008C20" || version == "V200R008C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R009C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:svn5600_firmware" ) {
  if( version == "V200R003C00" || version == "V200R003C10" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R003C10SPCa00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R003C10SPCa00" );
      security_message( port: 0, data: report);
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:svn5800_firmware" ) {
  if( version == "V200R003C00" || version == "V200R003C10" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R003C10SPCa00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R003C10SPCa00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:svn5800-c_firmware" ) {
  if( version == "V200R003C00" || version == "V200R003C10" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R003C10SPCa00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R003C10SPCa00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:semg9811_firmware" ) {
  if( version == "V300R001C01SPC500" || version == "V300R001C01SPC500T" || version == "V300R001C01SPC700" || version == "V300R001C01SPCA00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R002C20SPC500+V500R002SPH015" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R002C20SPC500+V500R002SPH015" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:secospace_usg6300_firmware" ) {
  if( version == "V100R001C10" || version == "V100R001C20" || version == "V100R001C30" || version == "V500R001C00" ||
      version == "V500R001C20" || version == "V500R001C30" || version == "V500R001C50" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R001C60SPC500+V500R001SPH015" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC500+V500R001SPH015" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:secospace_usg6500_firmware" ) {
  if( version == "V100R001C10" || version == "V100R001C20" || version == "V100R001C30" || version == "V500R001C00" ||
      version == "V500R001C20" || version == "V500R001C30" || version == "V500R001C50" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R001C60SPC500+V500R001SPH015" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC500+V500R001SPH015" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:secospace_usg6600_firmware" ) {
  if( version == "V100R001C00" || version == "V100R001C10" || version == "V100R001C20" || version == "V100R001C30" ||
      version == "V500R001C00" || version == "V500R001C20" || version == "V500R001C30" || version == "V500R001C50" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R001C60SPC500+V500R001SPH015" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC500+V500R001SPH015" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:softco_firmware" ) {
  if( version == "V200R001C01SPC300" || version == "V200R001C01SPC400" || version == "V200R001C01SPC500" || version == "V200R001C01SPC600" ||
      version == "V200R001C01SPH703" || version == "V200R003C00SPC100" || version == "V200R003C00SPC200" || version == "V200R003C00SPC300" ||
      version == "V200R003C00SPC500" || version == "V200R003C20" ) {
    if( ! patch || version_is_less( version: patch, test_version: "eSpace U1981 V200R003C30SPC500" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "eSpace U1981 V200R003C30SPC500" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:te30_firmware" ) {
  if( version == "V100R001C02SPC100" || version == "V100R001C02SPC200" || version == "V100R001C10" || version == "V500R002C00SPC200" ||
      version == "V500R002C00SPC600" || version == "V500R002C00SPC700" || version == "V500R002C00SPC900" || version == "V500R002C00SPCB00" ||
      version == "V600R006C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V600R006C00SPC400" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:te40_firmware" ) {
  if( version == "V500R002C00SPC600" || version == "V500R002C00SPC700" || version == "V500R002C00SPC900" ||
      version == "V500R002C00SPCB00" || version == "V600R006C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V600R006C00SPC400" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:te50_firmware" ) {
  if( version == "V500R002C00SPC600" || version == "V500R002C00SPCB00" || version == "V600R006C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V600R006C00SPC400" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:te60_firmware" ) {
  if( version == "V100R001C01SPC100" || version == "V100R001C10" || version == "V100R001C10SPC300" || version == "V100R001C10SPC400" ||
      version == "V100R001C10SPC500" || version == "V100R001C10SPC600" || version == "V100R001C10SPC800" || version == "V100R003C00" ||
      version == "V500R002C00" || version == "V500R002C00SPC100" || version == "V500R002C00SPC200" || version == "V500R002C00SPC300" ||
      version == "V500R002C00SPC600" || version == "V500R002C00SPC700" || version == "V500R002C00SPC800" || version == "V500R002C00SPC900" ||
      version == "V500R002C00SPCA00" || version == "V500R002C00SPCB00" || version == "V600R006C00" || version == "V600R006C00SPC200" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V600R006C00SPC400" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:tp3206_firmware" ) {
  if( version == "V100R002C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V100R002C00SPC800" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V100R002C00SPC800" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:usg9500_firmware" ) {
  if( version == "V300R001C01" || version == "V300R001C20" || version == "V500R001C00" || version == "V500R001C20" ||
      version == "V500R001C30" || version == "V500R001C50" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R001C60SPC500+V500R001SPH015" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC500+V500R001SPH015" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:usg9520_firmware" ) {
  if( version == "V300R001C01SPC800PWE" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R002C10SPC100" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R002C10SPC100" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:usg9560_firmware" ) {
  if( version == "V300R001C20SPC300" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R002C10SPC100" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R002C10SPC100" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:vp9660_firmware" ) {
  if( version == "V200R001C02SPC100" || version == "V200R001C02SPC200" || version == "V200R001C02SPC300" || version == "V200R001C02SPC300T" ||
      version == "V200R001C02SPC400" || version == "V200R001C30SPC100" || version == "V200R001C30SPC100B015T" || version == "V200R001C30SPC101" ||
      version == "V200R001C30SPC101TB015" || version == "V200R001C30SPC102T" || version == "V200R001C30SPC103T" || version == "V200R001C30SPC104T" ||
      version == "V200R001C30SPC200" || version == "V200R001C30SPC200B022T" || version == "V200R001C30SPC201B023T" || version == "V200R001C30SPC202B025T" ||
      version == "V200R001C30SPC203T" || version == "V200R001C30SPC206T" || version == "V200R001C30SPC207T" || version == "V200R001C30SPC208T" ||
      version == "V200R001C30SPC209T" || version == "V200R001C30SPC300" || version == "V200R001C30SPC400" || version == "V200R001C30SPC400B001" ||
      version == "V200R001C30SPC400T" || version == "V200R001C30SPC401T" || version == "V200R001C30SPC402T" || version == "V200R001C30SPC403T" ||
      version == "V200R001C30SPC404T" || version == "V200R001C30SPC405T" || version == "V200R001C30SPC600" || version == "V200R001C30SPC700" ||
      version == "V200R001C30SPC700T" || version == "V200R001C30SPC701T" || version == "V200R001C30SPC702T" || version == "V200R001C30SPC703T" ||
      version == "V200R001C30SPC800" || version == "V200R001C30SPC800T" || version == "V200R001C30SPC900" || version == "V200R001C30SPCA00" ||
      version == "V200R001C30SPCA00T" || version == "V200R001C30SPCA01" || version == "V200R001C30SPCA01T" || version == "V200R001C30SPCA02T" ||
      version == "V200R001C30SPCB00" || version == "V200R001C30SPCC00" || version == "V200R001C30SPCD00" || version == "V200R001C30SPCD00T" ||
      version == "V200R001C30SPCD01T" || version == "V200R001C30SPCD02T" || version == "V200R001C30SPCD03T" || version == "V200R001C30SPCD04T" ||
      version == "V200R001C30SPCD05T" || version == "V200R001C30SPCE00" || version == "V200R001C30SPCE01T" || version == "V200R001C30SPCF00" ||
      version == "V200R001C30SPCG00" || version == "V200R001C30SPCH00" || version == "V200R001C30SPCI00" || version == "V200R001C30SPCJ00" ||
      version == "V500R002C00" || version == "V500R002C00SPC001T" || version == "V500R002C00SPC200" || version == "V500R002C00SPC200T" ||
      version == "V500R002C00SPC201T" || version == "V500R002C00SPC203T" || version == "V500R002C00SPC204T" || version == "V500R002C00SPC205T" ||
      version == "V500R002C00SPC206T" || version == "V500R002C00SPC300" || version == "V500R002C00SPC400" || version == "V500R002C00SPC500" ||
      version == "V500R002C00SPC600" || version == "V500R002C00SPC700" || version == "V500R002C00SPC800" || version == "V500R002C00SPC900" ||
      version == "V500R002C00SPC900T" || version == "V500R002C00SPC901T" || version == "V500R002C00SPCA00" || version == "V500R002C00SPCB00" ||
      version == "V500R002C00SPCB01T" || version == "V500R002C00SPCC00" || version == "V500R002C00SPCD00" || version == "V500R002C00T" ||
      version == "V500R002C10" || version == "V500R002C10SPC100" || version == "V500R002C10SPC100T" || version == "V500R002C10T" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V500R002C10SPC800" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R002C10SPC800" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:viewpoint_8660_firmware" ) {
  if( version == "V100R008C03B013SP02" || version == "V100R008C03B013SP03" || version == "V100R008C03B013SP04" || version == "V100R008C03SPC100" ||
      version == "V100R008C03SPC200" || version == "V100R008C03SPC300" || version == "V100R008C03SPC400" || version == "V100R008C03SPC500" ||
      version == "V100R008C03SPC600" || version == "V100R008C03SPC700" || version == "V100R008C03SPC800" || version == "V100R008C03SPC900" ||
      version == "V100R008C03SPCA00" || version == "V100R008C03SPCB00" || version == "V100R008C03SPCC00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V100R008C03SPCe00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V100R008C03SPCe00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:viewpoint_9030_firmware" ) {
  if( version == "V100R011C02SPC100" || version == "V100R011C03B012SP15" || version == "V100R011C03B012SP16" || version == "V100R011C03B015SP03" ||
      version == "V100R011C03LGWL01SPC100" || version == "V100R011C03LGWL01SPC100B012" || version == "V100R011C03SPC100" ||
      version == "V100R011C03SPC200" || version == "V100R011C03SPC300" || version == "V100R011C03SPC400" || version == "V100R011C03SPC500" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V100R011C03SPC800" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V100R011C03SPC800" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:espace_u1910_firmware" ) {
  if( version == "V100R001C20SPC300" || version == "V100R001C20SPC400" || version == "V100R001C20SPC500" || version == "V100R001C20SPC600" ||
      version == "V100R001C20SPH703" || version == "V200R003C00" || version == "V200R003C20" || version == "V200R003C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "eSpace U1981 V200R003C30SPC500" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "eSpace U1981 V200R003C30SPC500" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:espace_u1911_firmware" ) {
  if( version == "V100R001C20SPC300" || version == "V100R001C20SPC400" || version == "V100R001C20SPC500" || version == "V100R001C20SPC600" ||
      version == "V100R001C20SPH309" || version == "V100R001C20SPH703" || version == "V200R003C00" || version == "V200R003C20" || version == "V200R003C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "eSpace U1981 V200R003C30SPC500" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "eSpace U1981 V200R003C30SPC500" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:espace_u1930_firmware" ) {
  if( version == "V100R001C20SPC300" || version == "V100R001C20SPC400" || version == "V100R001C20SPC500" || version == "V100R001C20SPC600" ||
      version == "V100R001C20SPH703" || version == "V200R003C00" || version == "V200R003C20" || version == "V200R003C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "eSpace U1981 V200R003C30SPC500" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "eSpace U1981 V200R003C30SPC500" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:espace_u1960_firmware" ) {
  if( version == "V100R001C01SPC500" || version == "V100R001C20LCRW01T" || version == "V100R001C20SPC300" || version == "V100R001C20SPC400" ||
      version == "V100R001C20SPC600" || version == "V100R001C20SPC600T" || version == "V100R001C20SPH309" || version == "V100R001C20SPH703" ||
      version == "V200R003C00" || version == "V200R003C20" || version == "V200R003C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "eSpace U1981 V20V200R003C30SPC5000R003C30SPC200" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "eSpace U1981 V20V200R003C30SPC5000R003C30SPC200" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:espace_u1980_firmware" ) {
  if( version == "V100R001C01SPC500T" || version == "V100R001C20SPC300" || version == "V100R001C20SPC400" || version == "V100R001C20SPC500T" ||
      version == "V100R001C20SPC502" || version == "V100R001C20SPC600" || version == "V100R001C20SPH309" || version == "V100R001C20SPH703" ||
      version == "V200R003C00" || version == "V200R003C20" || version == "V200R003C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "eSpace U1981 V200R003C30SPC500" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "eSpace U1981 V200R003C30SPC500" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:espace_u1981_firmware" ) {
  if( version == "V100R001C20SPC300" || version == "V100R001C20SPC400" || version == "V100R001C20SPC500" || version == "V100R001C20SPC600" ||
      version == "V100R001C20SPC700" || version == "V100R001C20SPH702" || version == "V100R001C20SPH703" || version == "V100R001C30" ||
      version == "V200R003C00" || version == "V200R003C20" || version == "V200R003C30" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R003C30SPC500" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R003C30SPC500" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

exit( 99 );
