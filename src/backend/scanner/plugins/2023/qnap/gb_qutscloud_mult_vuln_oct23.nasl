# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qutscloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151200");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-17 07:57:13 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2023-32970", "CVE-2023-32973", "CVE-2023-32974");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTScloud Multiple Vulnerabilities (QSA-23-41, QSA-23-42)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qutscloud/detected");

  script_tag(name:"summary", value:"QNAP QuTScloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-32970: Null pointer dereference which could allow authenticated administrators to
  launch a denial of service (DoS)

  - CVE-2023-32973: Buffer copy without checking size of input which could allow authenticated
  administrators to execute code

  - CVE-2023-32974: A path traversal could allow users to read and expose sensitive data");

  script_tag(name:"affected", value:"QNAP QuTScloud c5.x.");

  script_tag(name:"solution", value:"Update to version c5.1.0.2498 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-41");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-42");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "c5.0.0", test_version_up: "c5.1.0.2498")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "c5.1.0.2498");
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
