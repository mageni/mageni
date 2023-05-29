# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:openmeetings";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149674");
  script_version("2023-05-16T09:08:27+0000");
  script_tag(name:"last_modification", value:"2023-05-16 09:08:27 +0000 (Tue, 16 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-15 07:25:15 +0000 (Mon, 15 May 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2023-29032");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache OpenMeetings 3.1.3 < 7.1.0 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apache_openmeetings_http_detect.nasl");
  script_mandatory_keys("apache/openmeetings/detected");

  script_tag(name:"summary", value:"Apache OpenMeetings is prone to an authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker that has gained access to certain private
  information can use this to act as other user.");

  script_tag(name:"affected", value:"Apache OpenMeetings version 3.1.3 and later prior to 7.1.0.");

  script_tag(name:"solution", value:"Update to version 7.1.0 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/j2d6mg3rzcphfd8vvvk09d8p4o9lvnqp");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/OPENMEETINGS-2764");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.1.3", test_version_up: "7.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
