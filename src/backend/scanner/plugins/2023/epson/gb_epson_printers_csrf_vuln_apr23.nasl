# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.170547");
  script_version("2023-08-23T05:05:12+0000");
  script_tag(name:"last_modification", value:"2023-08-23 05:05:12 +0000 (Wed, 23 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-21 08:20:32 +0000 (Mon, 21 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2023-27520");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Epson Printers CSRF Vulnerability (Apr 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_epson_printer_consolidation.nasl");
  script_mandatory_keys("epson/printer/detected");

  script_tag(name:"summary", value:"Multiple Epson printer models are prone to a cross-site request
  forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target
  host.");

  script_tag(name:"impact", value:"This vulnerability allows a remote unauthenticated attacker to
  hijack the authentication and perform unintended operations by having a logged-in user view a
  malicious page.");

  script_tag(name:"affected", value:"Epson Printers SC-T3250, SC-T3255, SC-T5250, SC-T5255, SC-T7250,
  SC-T7255, SC-T5250D, SC-T5255D, SC-T7250D, SC-T7255D, SC-P7050, SC-P9050, SC-P6050, SC-P8050,
  SC-P20050, SC-S80650, SC-S60650, SC-S40650, SC-S60650L, SC-S80650L, SC-F7200, SC-F6350, SC-F9450,
  SC-F9450H, SC-F2150, TM-C7500, TM-C3500, TM-C3400, PX-B510, PX-B500, PX-5800, PX-5002, PX-5V, PX-7V,
  SC-PX7V2, SC-PX5V2, SC-PX3V, PX-6250S, PX-6550, PX-7500N, PX-7550, PX-7550S, PX-9500N, PX-9550,
  PX-9550S, PX-20000, STYLUS PRO GS6000, PX-W8000, PX-F8000, PX-F8000M, PX-F10000, PX-H6000, PX-H7000,
  PX-H8000, PX-H9000, PX-H10000, SC-T3050, SC-T5050, SC-T7050, SC-T10050, SC-S30650, SC-S50650,
  SC-S70650, SC-F6000, SC-F7100, SC-F6200, SC-F9200, SC-F9350 and SC-F9350.");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN82424996/");
  script_xref(name:"URL", value:"https://www.epson.jp/support/misc_t/230308_oshirase.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/38138.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/38140.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/38142.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/38144.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/38146.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/37651.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/38268.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/38264.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/38266.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/38314.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/37638.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/37628.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/37673.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/38316.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/37679.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/37675.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/37677.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/38585.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/37552.htm");
  script_xref(name:"URL", value:"https://www.epson.jp/dl_soft/readme/37554.htm");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("epson_printers.inc");

cpe_list = make_list( "cpe:/o:epson:sc-t3250_firmware",
                      "cpe:/o:epson:sc-t3255_firmware",
                      "cpe:/o:epson:sc-t5250_firmware",
                      "cpe:/o:epson:sc-t5255_firmware",
                      "cpe:/o:epson:sc-t7250_firmware",
                      "cpe:/o:epson:sc-t7255_firmware",
                      "cpe:/o:epson:sc-t5250d_firmware",
                      "cpe:/o:epson:sc-t5255d_firmware",
                      "cpe:/o:epson:sc-t7250d_firmware",
                      "cpe:/o:epson:sc-t7255d_firmware",
                      "cpe:/o:epson:sc-p5050g_firmware",
                      "cpe:/o:epson:sc-p5050v_firmware",
                      "cpe:/o:epson:sc-p7050g_firmware",
                      "cpe:/o:epson:sc-p7050v_firmware",
                      "cpe:/o:epson:sc-p9050g_firmware",
                      "cpe:/o:epson:sc-p9050v_firmware",
                      "cpe:/o:epson:sc-p6050_firmware",
                      "cpe:/o:epson:sc-p8050_firmware",
                      "cpe:/o:epson:sc-p20050_firmware",
                      "cpe:/o:epson:sc-s80650_firmware",
                      "cpe:/o:epson:sc-s60650_firmware",
                      "cpe:/o:epson:sc-s40650_firmware",
                      "cpe:/o:epson:sc-s60650l_firmware",
                      "cpe:/o:epson:sc-s80650l_firmware",
                      "cpe:/o:epson:sc-f7200_firmware",
                      "cpe:/o:epson:sc-f6350_firmware",
                      "cpe:/o:epson:sc-f9450_firmware",
                      "cpe:/o:epson:sc-f9450h_firmware",
                      "cpe:/o:epson:sc-f2150_firmware",
                      "cpe:/o:epson:tm-c7500_firmware",
                      "cpe:/o:epson:tm-c3500_firmware",
                      "cpe:/o:epson:tm-c3400_firmware",
                      "cpe:/o:epson:px-b510_firmware",
                      "cpe:/o:epson:px-b500_firmware",
                      "cpe:/o:epson:px-5800_firmware",
                      "cpe:/o:epson:px-5002_firmware",
                      "cpe:/o:epson:px-5v_firmware",
                      "cpe:/o:epson:px-7v_firmware",
                      "cpe:/o:epson:sc-px7v2_firmware",
                      "cpe:/o:epson:sc-px5v2_firmware",
                      "cpe:/o:epson:sc-px3v_firmware",
                      "cpe:/o:epson:px-6250s_firmware",
                      "cpe:/o:epson:px-6550_firmware",
                      "cpe:/o:epson:px-7500n_firmware",
                      "cpe:/o:epson:px-7550_firmware",
                      "cpe:/o:epson:px-7550s_firmware",
                      "cpe:/o:epson:px-9500n_firmware",
                      "cpe:/o:epson:px-9550_firmware",
                      "cpe:/o:epson:px-9550s_firmware",
                      "cpe:/o:epson:px-20000_firmware",
                      "cpe:/o:epson:stylus_pro_gs6000_firmware",
                      "cpe:/o:epson:px-w8000_firmware",
                      "cpe:/o:epson:px-f8000_firmware",
                      "cpe:/o:epson:px-f8000m_firmware",
                      "cpe:/o:epson:px-f10000_firmware",
                      "cpe:/o:epson:px-h6000_firmware",
                      "cpe:/o:epson:px-h7000_firmware",
                      "cpe:/o:epson:px-h8000_firmware",
                      "cpe:/o:epson:px-h9000_firmware",
                      "cpe:/o:epson:px-h10000_firmware",
                      "cpe:/o:epson:sc-t3050_firmware",
                      "cpe:/o:epson:sc-t5050_firmware",
                      "cpe:/o:epson:sc-t7050_firmware",
                      "cpe:/o:epson:sc-t10050_firmware",
                      "cpe:/o:epson:sc-s30650_firmware",
                      "cpe:/o:epson:sc-s50650_firmware",
                      "cpe:/o:epson:sc-s70650_firmware",
                      "cpe:/o:epson:sc-f6000_firmware",
                      "cpe:/o:epson:sc-f7100_firmware",
                      "cpe:/o:epson:sc-f6200_firmware",
                      "cpe:/o:epson:sc-f9200_firmware",
                      "cpe:/o:epson:sc-f9350_firmware",
                      "cpe:/o:epson:sc-f2000_firmware" );

if ( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if ( ! version = get_app_version( cpe:cpe, port:port ) )
  exit( 0 );

if ( cpe =~ "^cpe:/o:epson:sc-t325[05]_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"DN015N5" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"DN015N5" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe =~ "^cpe:/o:epson:sc-t525[05]_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"DM015N5" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"DM015N5" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe =~ "^cpe:/o:epson:sc-t725[05]_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"DW015N5" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"DW015N5" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe =~ "^cpe:/o:epson:sc-t525[05]d_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"MM015N5" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"MM015N5" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe =~ "^cpe:/o:epson:sc-t725[05]d_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"MW015N5" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"MW015N5" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe =~ "^cpe:/o:epson:sc-p5050[vg]_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"N027N2" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"N027N2" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe =~ "^cpe:/o:epson:sc-p7050[vg]_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"LN002N6" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"LN002N6" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe =~ "^cpe:/o:epson:sc-p9050[vg]_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"LW002N6" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"LW002N6" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:sc-p6050_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"NN002N6" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"NN002N6" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:sc-p8050_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"NW002N6" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"NW002N6" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:sc-p20050_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"FW026N6" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"FW026N6" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:sc-s80650_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"SA011MBa" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"SA011MBa" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:sc-s60650_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"HA027K2b" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"HA027K2b" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:sc-s40650_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"BA027K2b" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"BA027K2b" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:sc-s60650l_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"HC001LAa" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"HC001LAa" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:sc-s80650l_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"SC024M3a" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"SC024M3a" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:sc-f7200_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"CO011LA" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"CO011LA" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:sc-f9450_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"MT026L5a" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"MT026L5a" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:sc-f9450h_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"MU026L5a" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"MU026L5a" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:sc-f2150_firmware" ) {
  if ( epson_version_is_less( version:version, test_version:"LA015K4" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"LA015K4" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:tm-c3500_firmware" ) {
  if ( version_is_less( version:version, test_version:"WAM32500" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"WAM32500" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if ( cpe == "^cpe:/o:epson:tm-c7500_firmware" ) {
  if ( version_is_less( version:version, test_version:"WAI34400" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"WAI34400" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

# nb: For all other models not added above, there will be no firmware release
report = report_fixed_ver( installed_version:version, fixed_version:"None, see the references for mitigation steps." );
security_message( port:port, data:report );

exit( 0 ); # nb: No exit(99); on purpose...


