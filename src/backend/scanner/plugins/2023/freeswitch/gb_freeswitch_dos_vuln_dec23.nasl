# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freeswitch:freeswitch";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126658");
  script_version("2024-02-02T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:11 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2023-12-29 12:27:43 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 02:23:51 +0000 (Fri, 02 Feb 2024)");

  script_cve_id("CVE-2023-51443");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreeSWITCH < 1.10.11 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_freeswitch_consolidation.nasl");
  script_mandatory_keys("freeswitch/detected");

  script_tag(name:"summary", value:"FreeSWITCH is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"FreeSWITCH is susceptible to denial of service (DoS) due to a
  race condition in the hello handshake phase of the DTLS protocol. This attack can be done
  continuously, thus denying new DTLS-SRTP encrypted calls during the attack.");

  script_tag(name:"affected", value:"FreeSWITCH prior to version 1.10.11.");

  script_tag(name:"solution", value:"Update to version 1.10.11 or later.");

  script_xref(name:"URL", value:"https://github.com/signalwire/freeswitch/security/advisories/GHSA-39gv-hq72-j6m6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.10.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.10.11");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);