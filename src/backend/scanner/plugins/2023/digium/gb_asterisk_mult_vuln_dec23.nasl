# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151405");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-15 04:00:32 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-20 16:32:00 +0000 (Wed, 20 Dec 2023)");

  script_cve_id("CVE-2023-37457", "CVE-2023-49294", "CVE-2023-49786");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Multiple Vulnerabilities (Dec 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-37457: PJSIP_HEADER dialplan function can overwrite memory/cause crash when using
  'update'

  - CVE-2023-49294: Path traversal via AMI GetConfig allows access to outside files

  - CVE-2023-49786: Denial of Service via DTLS Hello packets during call initiation

  - No CVE: PJSIP logging allows attacker to inject fake Asterisk log entries");

  script_tag(name:"affected", value:"Asterisk Open Source prior to 18.20.1, 20.x prior to 20.5.1,
  21.x prior to 21.0.1 and Certified Asterisk prior to 18.9-cert6");

  script_tag(name:"solution", value:"Update to version 18.20.1, 20.5.1, 21.0.1, 18.9-cert6 or
  later.");

  script_xref(name:"URL", value:"https://github.com/asterisk/asterisk/security/advisories/GHSA-8857-hfmw-vg8f");
  script_xref(name:"URL", value:"https://github.com/asterisk/asterisk/security/advisories/GHSA-hxj9-xwr8-w8pq");
  script_xref(name:"URL", value:"https://github.com/asterisk/asterisk/security/advisories/GHSA-5743-x3p5-3rg7");
  script_xref(name:"URL", value:"https://github.com/asterisk/asterisk/security/advisories/GHSA-98rc-4j27-74hh");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^18\.") {
  if (version =~ "^18\.[0-9]cert") {
    if (revcomp(a: version, b: "18.9cert6") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "18.9-cert6");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "18.20.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "18.20.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version_in_range_exclusive(version: version, test_version_lo: "20.0", test_version_up: "20.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.5.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "21.0", test_version_up: "21.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.0.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
