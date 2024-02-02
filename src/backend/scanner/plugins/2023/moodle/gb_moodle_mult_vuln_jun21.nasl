# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126530");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-25 08:31:42 +0000 (Wed, 25 Oct 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 20:36:00 +0000 (Tue, 29 Jun 2021)");

  script_cve_id("CVE-2021-21809", "CVE-2021-27131", "CVE-2021-32244");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Moodle 3.10.x <= 3.10.11 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-21809: Authenticated administrator could define spellcheck settings via the web
  interface.

  - CVE-2021-27131: Stored cross-site scripting due to the improper input sanitization on the
  'Additional HTML Section' of the /admin/settings.php page.

  - CVE-2021-32244: Cross site scripting allows to execute web script or HTML via the 'Description'
  field.");

  script_tag(name:"affected", value:"Moodle versions 3.10.x through 3.10.11.");

  script_tag(name:"solution", value:"No solution was made available by the vendor.

  Note: Moodle 3.10.x reached end of life in May 2022. Users should upgrade to newer versions
  as it addresses numerous other issues from the previous versions.");

  script_xref(name:"URL", value:"https://www.rapid7.com/db/vulnerabilities/moodle-cve-2021-32244/");
  script_xref(name:"URL", value:"https://www.rapid7.com/db/vulnerabilities/moodle-cve-2021-21809/");
  script_xref(name:"URL", value:"https://github.com/p4nk4jv/CVEs-Assigned/blob/master/Moodle-3.10.1-CVE-2021-27131.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^3\.10\.[0-9]([0-9])?") {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
