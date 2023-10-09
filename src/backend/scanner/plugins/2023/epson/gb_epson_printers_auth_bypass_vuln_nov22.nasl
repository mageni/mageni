# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.170545");
  script_version("2023-08-23T05:05:12+0000");
  script_tag(name:"last_modification", value:"2023-08-23 05:05:12 +0000 (Wed, 23 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-21 12:37:36 +0000 (Mon, 21 Aug 2023)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");

  script_cve_id("CVE-2022-36133");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Epson Printers Authentication Bypass Vulnerability (Nov 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_epson_printer_consolidation.nasl");
  script_mandatory_keys("epson/printer/detected");

  script_tag(name:"summary", value:"Epson Printers TM-C3500 and TM-C7500 series are prone to an
  authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target
  host.");

  script_tag(name:"impact", value:"A successful attack would allow the attacker to change the
  printer's communication settings. A printer whose communication settings have been changed becomes
  temporarily unusable.");

  script_tag(name:"affected", value:"Epson Printers TM-C3500 and TM-C7500 series.");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://download.epson-biz.com/epson/epson_public_document.php?name=Infomation_history.pdf");
  script_xref(name:"URL", value:"https://download.epson-biz.com/epson/epson_public_document.php?name=tmc3500_WAM.pdf");
  script_xref(name:"URL", value:"https://download.epson-biz.com/epson/epson_public_document.php?name=tmc7500_WAI.pdf");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/o:epson:tm-c3500_firmware",
                      "cpe:/o:epson:tm-c3510_firmware",
                      "cpe:/o:epson:tm-c3520_firmware",
                      "cpe:/o:epson:tm-c7500_firmware",
                      "cpe:/o:epson:tm-c7500g_firmware",
                      "cpe:/o:epson:tm-c7510_firmware",
                      "cpe:/o:epson:tm-c7510g_firmware",
                      "cpe:/o:epson:tm-c7520_firmware",
                      "cpe:/o:epson:tm-c7520g_firmware" );

if ( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if ( ! version = get_app_version( cpe:cpe, port:port ) )
  exit( 0 );

if ( cpe =~ "^cpe:/o:epson:tm-c35[012]0_firmware" ) {
  if ( version_is_less( version:version, test_version:"WAM32200" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"WAM32200" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe =~ "^cpe:/o:epson:tm-c75[012]0g?_firmware" ) {
  if ( version_is_less( version:version, test_version:"WAI34200" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"WAI34200" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
