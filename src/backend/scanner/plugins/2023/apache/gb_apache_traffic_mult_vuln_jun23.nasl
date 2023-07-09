# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170483");
  script_version("2023-06-16T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-06-16 05:06:18 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-14 19:54:38 +0000 (Wed, 14 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2022-47184", "CVE-2023-30631", "CVE-2023-33933");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Traffic Server (ATS) 8.x <= 8.1.6, 9.x <= 9.2.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apache_traffic_detect.nasl");
  script_mandatory_keys("apache_trafficserver/installed");

  script_tag(name:"summary", value:"Apache Traffic Server (ATS) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-47184: The TRACE method can be used to disclose network information.

  - CVE-2023-30631: Configuration option to block the PUSH method in ATS didn't work.

  - CVE-2023-33933: s3_auth plugin problem with hash calculation.");

  script_tag(name:"affected", value:"Apache Traffic Server version 8.x through 8.1.6 and 9.x
  through 9.2.0.");

  script_tag(name:"solution", value:"Update to version 8.1.7, 9.2.1 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/tns2b4khyyncgs5v5p9y35pobg9z2bvs");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.7");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
