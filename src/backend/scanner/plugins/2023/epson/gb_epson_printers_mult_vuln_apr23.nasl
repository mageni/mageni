# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.170546");
  script_version("2023-08-23T05:05:12+0000");
  script_tag(name:"last_modification", value:"2023-08-23 05:05:12 +0000 (Wed, 23 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-21 08:20:32 +0000 (Mon, 21 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2023-23572", "CVE-2023-27520");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Epson Printers Multiple Vulnerabilities (Apr 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_epson_printer_consolidation.nasl");
  script_mandatory_keys("epson/printer/detected");

  script_tag(name:"summary", value:"Multiple Epson printer models are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target
  host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-23572: Cross-site scripting (XSS)

  - CVE-2023-27520: Cross-site request forgery (CSRF)");

  script_tag(name:"affected", value:"Epson Printers LP-9200PS2, LP-9200PS3, LP-8200C, LP-9600,
  LP-9600S, LP-9300, LP-8500C, LP-8700PS3, LP-9800C, LP-S5500, LP-9200B, LP-9200C, LP-S4500, LP-S6500,
  LP-S7000, LP-S5000, LP-S4000, LP-S6000, LP-S5300, LP-S5300R, LP-S300N, LP-S310N, LP-S3000,
  LP-S3000R, LP-S3000Z, LP-S3000PS, LP-S7500, LP-S7500PS, LP-S3500, LP-S4200, LP-S9000, LP-S7100,
  LP-S8100, PRIFNW1, PRIFNW1S, PRIFNW2, PRIFNW2AC, PRIFNW2S, PRIFNW2SAC, PRIFNW3, PRIFNW3S, PRIFNW6,
  PRIFNW7, PRIFNW7U, PRIFNW7S, PA-W11G, PA-W11G2, ESNSB1, ESNSB2 and ESIFNW1.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN82424996/");
  script_xref(name:"URL", value:"https://www.epson.jp/support/misc_t/230308_oshirase.htm");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/o:epson:lp-9200ps2_firmware",
                      "cpe:/o:epson:lp-9200ps3_firmware",
                      "cpe:/o:epson:lp-8200c_firmware",
                      "cpe:/o:epson:lp-9600_firmware",
                      "cpe:/o:epson:lp-9600s_firmware",
                      "cpe:/o:epson:lp-9300_firmware",
                      "cpe:/o:epson:lp-8500c_firmware",
                      "cpe:/o:epson:lp-8700ps3_firmware",
                      "cpe:/o:epson:lp-9800c_firmware",
                      "cpe:/o:epson:lp-s5500_firmware",
                      "cpe:/o:epson:lp-9200b_firmware",
                      "cpe:/o:epson:lp-9200c_firmware",
                      "cpe:/o:epson:lp-s4500_firmware",
                      "cpe:/o:epson:lp-s6500_firmware",
                      "cpe:/o:epson:lp-s7000_firmware",
                      "cpe:/o:epson:lp-s5000_firmware",
                      "cpe:/o:epson:lp-s4000_firmware",
                      "cpe:/o:epson:lp-s6000_firmware",
                      "cpe:/o:epson:lp-s5300_firmware",
                      "cpe:/o:epson:lp-s5300r_firmware",
                      "cpe:/o:epson:lp-s300n_firmware",
                      "cpe:/o:epson:lp-s310n_firmware",
                      "cpe:/o:epson:lp-s3000_firmware",
                      "cpe:/o:epson:lp-s3000r_firmware",
                      "cpe:/o:epson:lp-s3000z_firmware",
                      "cpe:/o:epson:lp-s3000ps_firmware",
                      "cpe:/o:epson:lp-s7500_firmware",
                      "cpe:/o:epson:lp-s7500ps_firmware",
                      "cpe:/o:epson:lp-s3500_firmware",
                      "cpe:/o:epson:lp-s4200_firmware",
                      "cpe:/o:epson:lp-s9000_firmware",
                      "cpe:/o:epson:lp-s7100_firmware",
                      "cpe:/o:epson:lp-s8100_firmware",
                      "cpe:/o:epson:prifnw1_firmware",
                      "cpe:/o:epson:prifnw1s_firmware",
                      "cpe:/o:epson:prifnw2_firmware",
                      "cpe:/o:epson:prifnw2ac_firmware",
                      "cpe:/o:epson:prifnw2s_firmware",
                      "cpe:/o:epson:prifnw2sac_firmware",
                      "cpe:/o:epson:prifnw3_firmware",
                      "cpe:/o:epson:prifnw3s_firmware",
                      "cpe:/o:epson:prifnw6_firmware",
                      "cpe:/o:epson:prifnw7_firmware",
                      "cpe:/o:epson:prifnw7u_firmware",
                      "cpe:/o:epson:prifnw7s_firmware",
                      "cpe:/o:epson:pa-w11g_firmware",
                      "cpe:/o:epson:pa-w11g2_firmware",
                      "cpe:/o:epson:esnsb1_firmware",
                      "cpe:/o:epson:esnsb2_firmware",
                      "cpe:/o:epson:esifnw1_firmware" );

if ( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if ( ! version = get_app_version( cpe:cpe, port:port ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None, see the references for mitigation steps." );
security_message( port:port, data:report );

exit( 0 ); # nb: No exit(99); on purpose...
