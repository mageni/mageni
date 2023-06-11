# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openldap:openldap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104768");
  script_version("2023-05-31T09:08:55+0000");
  script_tag(name:"last_modification", value:"2023-05-31 09:08:55 +0000 (Wed, 31 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-30 10:41:15 +0000 (Tue, 30 May 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2023-2953");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenLDAP NPD Vulnerability (May 2023)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openldap_consolidation.nasl");
  script_mandatory_keys("openldap/detected");

  script_tag(name:"summary", value:"OpenLDAP is prone to a NULL pointer dereference (NPD)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in OpenLDAP that can cause a null
  pointer dereference in the ber_memalloc_x() function.");

  script_tag(name:"affected", value:"OpenLDAP versions prior to 2.5.14 and 2.6.x prior to 2.6.4.");

  # nb: Both changelogs linked below contains fixes having a "ITS#9904" reference for the bug number
  script_tag(name:"solution", value:"Update to version 2.5.14, 2.6.4 or later.");

  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9904");
  script_xref(name:"URL", value:"https://openldap.org/software/release/changes.html");
  script_xref(name:"URL", value:"https://openldap.org/software/release/changes_lts.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2210651");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2023-2953");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.5.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.6.0", test_version_up: "2.6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.6.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
