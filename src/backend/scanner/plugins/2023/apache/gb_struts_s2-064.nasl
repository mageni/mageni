# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104801");
  script_version("2023-06-16T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-06-16 05:06:18 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-14 10:18:03 +0000 (Wed, 14 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2023-34396");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts Security Update (S2-064)");

  script_category(ACT_GATHER_INFO);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_tag(name:"summary", value:"Apache Struts is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When a Multipart request has non-file normal form fields, Struts
  used to bring them into memory as Strings without checking their sizes. This could lead to OOM if
  developer has set struts.multipart.maxSize to a value equal or greater than the available
  memory.");

  script_tag(name:"affected", value:"Apache Struts version 2.0.0 through 6.1.2.");

  script_tag(name:"solution", value:"- Update to version 2.5.31, 6.1.2.1 or later

  - Workaround: Set struts.multipart.maxSize to a value much much smaller than the available memory

  Note: Please set an override for this result if only the workaround has been applied");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-064");
  script_xref(name:"Advisory-ID", value:"S2-064");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2.0.0", test_version_up: "2.5.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

# nb: There was no version like e.g. 3.0, 4.0 and so on
if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.1.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
