# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126541");
  script_version("2023-11-23T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-11-23 05:06:17 +0000 (Thu, 23 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-15 10:45:42 +0000 (Wed, 15 Nov 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-21 00:45:00 +0000 (Tue, 21 Nov 2023)");

  script_cve_id("CVE-2023-39199", "CVE-2023-39203", "CVE-2023-39205", "CVE-2023-39206",
                "CVE-2023-43582", "CVE-2023-43588");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zoom Client < 5.16.0 Multiple Vulnerabilities (ZSB-23047, ZSB-23049, ZSB-23050, ZSB-23051, ZSB-23052, ZSB-23055) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_zoom_client_smb_login_detect.nasl");
  script_mandatory_keys("zoom/client/win/detected");

  script_tag(name:"summary", value:"The Zoom Client is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-39199 / ZSB-23051: Cryptographic issues with In-Meeting Chat for some Zoom clients may
  allow a privileged user to conduct an information disclosure via network access.

  - CVE-2023-39203 / ZSB-23047: Uncontrolled resource consumption in Zoom Team Chat for Zoom
  Desktop Client for Windows may allow an unauthenticated user to conduct a disclosure of
  information via network access.

  - CVE-2023-39205 / ZSB-23049: Improper conditions check in Zoom Team Chat for Zoom clients may
  allow an authenticated user to conduct a denial of service via network access.

  - CVE-2023-39206 / ZSB-23050: Buffer overflow in some Zoom clients may allow an unauthenticated
  user to conduct a denial of service via network access.

  - CVE-2023-43582 / ZSB-23055: Improper authorization in some Zoom clients may allow an authorized
  user to conduct an escalation of privilege via network access.

  - CVE-2023-43588 / ZSB-23052: Insufficient control flow management in some Zoom clients may allow
  an authenticated user to conduct an information disclosure via network access.");

  script_tag(name:"affected", value:"Zoom Client prior to version 5.16.0.");

  script_tag(name:"solution", value:"Update to version 5.16.0 or later.");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.16.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.16.0", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
