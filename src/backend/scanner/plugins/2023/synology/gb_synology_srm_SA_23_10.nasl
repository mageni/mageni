# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:router_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150783");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-28 04:38:34 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Router Manager < 1.3.1-9346-6 Multiple Vulnerabilities (Synology-SA-23:10)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities allow remote attackers to read
  specific files, obtain sensitive information, and inject arbitrary web script or HTML,
  man-in-the-middle attackers to bypass security constraint, and remote authenticated users to
  execute arbitrary commands and conduct denial-of-service attacks via a susceptible version of
  Synology Router Manager (SRM).");

  script_tag(name:"affected", value:"Synology Router Manager version 1.3.x prior to 1.3.1-9346-6.");

  script_tag(name:"solution", value:"Update to firmware version 1.3.1-9346-6 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_23_10");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if ((version =~ "^1\.3") && (revcomp(a: version, b: "1.3.1-9346-6") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.1-9346-6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
