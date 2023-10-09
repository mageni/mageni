# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.170544");
  script_version("2023-08-22T05:06:00+0000");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-21 08:20:32 +0000 (Mon, 21 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2023-38556");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Epson Printers DoS Vulnerability (Aug 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_epson_printer_consolidation.nasl");
  script_mandatory_keys("epson/printer/detected");

  script_tag(name:"summary", value:"Epson Printers EP-801A, EP-802A, EP-901A, EP-901F, EP-902A,
  PA-TCU1, PM-T960, PM-T990, PX-201, PX-502A, PX-601F and PX-602F are prone to a denial of service
  (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target
  host.");

  script_tag(name:"insight", value:"If you access the product's Web Config with a specific URL that
  turns off the power of the printer product, the power of the product may be turned off.");

  script_tag(name:"affected", value:"Epson Printers EP-801A, EP-802A, EP-901A, EP-901F, EP-902A,
  PA-TCU1, PM-T960, PM-T990, PX-201, PX-502A, PX-601F and PX-602F");

  script_tag(name:"solution", value:"The vendor advises to install and configure the printers
  according to the Security Guidebook and always place the printer inside a firewall-protected
  network.");

  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN61337171/");
  script_xref(name:"URL", value:"https://www.epson.jp/support/misc_t/230802_oshirase.htm");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/o:epson:ep-801a_firmware",
                      "cpe:/o:epson:ep-802a_firmware",
                      "cpe:/o:epson:ep-901a_firmware",
                      "cpe:/o:epson:ep-901f_firmware",
                      "cpe:/o:epson:ep-902a_firmware",
                      "cpe:/o:epson:pa-tcu1_firmware",
                      "cpe:/o:epson:pm-t960_firmware",
                      "cpe:/o:epson:pm-t990_firmware",
                      "cpe:/o:epson:px-201_firmware",
                      "cpe:/o:epson:px-502a_firmware",
                      "cpe:/o:epson:px-601f_firmware",
                      "cpe:/o:epson:px-602f_firmware" );

if ( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if ( ! version = get_app_version( cpe:cpe, port:port ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None, see the references for mitigation steps." );
security_message( port:port, data:report );

exit( 0 ); # nb: No exit(99); on purpose...
