# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170477");
  script_version("2023-05-24T09:09:06+0000");
  script_tag(name:"last_modification", value:"2023-05-24 09:09:06 +0000 (Wed, 24 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-23 09:03:02 +0000 (Tue, 23 May 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-2051", "CVE-2018-6530", "CVE-2022-26258", "CVE-2022-28958");

  script_name("D-Link Multiple DIR Devices Multiple Vulnerabilities (Sep 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"Multiple D-Link DIR devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Mirai BotNet variant MooBot leverages several vulnerabilities
  to compromise D-Link devices.");

  script_tag(name:"affected", value:"D-Link DIR-300, DIR-600, DIR-601, DIR-629, DIR-645, DIR-815,
  DIR-816L, DIR-817Lx, DIR-818Lx, DIR-820Lx, DIR-825, DIR-850L, DIR-860L, DIR-865L, DIR-868L,
  DIR-880L, DIR-885L/R, DIR-890L/R and DIR-895L/R devices.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that all models reached their End-of-Support Date, they are no longer
  supported, and firmware development has ceased. See vendor advisory for further recommendations.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10300");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10302");
  script_xref(name:"URL", value:"https://unit42.paloaltonetworks.com/moobot-d-link-devices/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:d-link:dir-300_firmware",
                      "cpe:/o:d-link:dir-600_firmware",
                      "cpe:/o:d-link:dir-601_firmware",
                      "cpe:/o:d-link:dir-629_firmware",
                      "cpe:/o:d-link:dir-645_firmware",
                      "cpe:/o:d-link:dir-815_firmware",
                      "cpe:/o:d-link:dir-816l_firmware",
                      "cpe:/o:d-link:dir-817lw_firmware",
                      "cpe:/o:d-link:dir-818lw_firmware",
                      "cpe:/o:d-link:dir-820l_firmware",
                      "cpe:/o:d-link:dir-820lw_firmware",
                      "cpe:/o:d-link:dir-825_firmware",
                      "cpe:/o:d-link:dir-850l_firmware",
                      "cpe:/o:d-link:dir-860l_firmware",
                      "cpe:/o:d-link:dir-865l_firmware",
                      "cpe:/o:d-link:dir-868l_firmware",
                      "cpe:/o:d-link:dir-880l_firmware",
                      "cpe:/o:d-link:dir-885l%2fr_firmware",
                      "cpe:/o:d-link:dir-890l%2fr_firmware",
                      "cpe:/o:d-link:dir-895l%2fr_firmware");

if ( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if ( ! version = get_app_version( cpe:cpe, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:port, data:report );
exit( 0 );
