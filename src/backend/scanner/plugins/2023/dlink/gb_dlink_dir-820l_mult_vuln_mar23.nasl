# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/o:d-link:dir-820l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170360");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-14 10:21:34 +0000 (Tue, 14 Mar 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2022-34973", "CVE-2023-25279", "CVE-2023-25280", "CVE-2023-25281",
                "CVE-2023-25282", "CVE-2023-25283");

  script_name("D-Link DIR-820L Devices Multiple Vulnerabilities (Mar 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-820L devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-34973: Buffer overflow via the nextPage parameter at ping.ccp.

  - CVE-2023-25279: OS Command injection vulnerability allows attackers to escalate privileges to
  root via a crafted payload.

  - CVE-2023-25280: OS Command injection vulnerability allows attackers to escalate privileges to
  root via a crafted payload with the ping_addr parameter to ping.ccp.

  - CVE-2023-25281: A stack overflow vulnerability existing in pingV4Msg component allows attackers
  to cause a denial of service via the nextPage parameter to ping.ccp.

  - CVE-2023-25282: A heap overflow vulnerability allows attackers to cause a denial of service via
  the config.log_to_syslog and log_opt_dropPackets parameters to mydlink_api.ccp.

  - CVE-2023-25283: A stack overflow vulnerability allows attackers to cause a denial of service via
  the reserveDHCP_HostName_1.1.1.0 parameter to lan.asp.");

  script_tag(name:"affected", value:"D-Link DIR-820L devices.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-820L reached its End-of-Support Date in 01.11.2017, it is no longer
  supported, and firmware development has ceased. See vendor advisory for further recommendations.");

  script_xref(name:"URL", value:"https://github.com/migraine-sudo/D_Link_Vuln/tree/main/cmd%20Inject%20In%20tools_AccountName");
  script_xref(name:"URL", value:"https://github.com/migraine-sudo/D_Link_Vuln/tree/main/stackoverflow%20%20in%20reserveDHCP_HostName_1.1.1.0");
  script_xref(name:"URL", value:"https://github.com/migraine-sudo/D_Link_Vuln/tree/main/cmd%20Inject%20in%20pingV4Msg");
  script_xref(name:"URL", value:"https://github.com/migraine-sudo/D_Link_Vuln/tree/main/stackoverflow%20cancelPing");
  script_xref(name:"URL", value:"https://github.com/migraine-sudo/D_Link_Vuln/tree/main/Permanent%20DDOS%20vulnerability%20in%20emailInfo");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/pages/product.aspx?id=00c2150966b046b58ba95d8ae3a8f73d");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
security_message( port:port, data:report );
exit( 0 );
