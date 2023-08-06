# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.26");
  script_cve_id("CVE-2023-3600");
  script_tag(name:"creation_date", value:"2023-07-12 06:24:29 +0000 (Wed, 12 Jul 2023)");
  script_version("2023-07-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-07-13 05:06:09 +0000 (Thu, 13 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-26) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-26");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-26/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1839703");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-3600: Use-after-free in workers
During the worker lifecycle, a use-after-free condition could have occurred, which could have led to a potentially exploitable crash.");

  script_tag(name:"affected", value:"Firefox version(s) below 115.0.2.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "115.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "115.0.2", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
