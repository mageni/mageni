# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redis:redis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150943");
  script_version("2023-09-08T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-09-08 05:06:21 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-07 05:08:19 +0000 (Thu, 07 Sep 2023)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2023-41053");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redis ACL Bypass Vulnerability (GHSA-q4jr-5p56-4xwc)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_mandatory_keys("redis/installed");

  script_tag(name:"summary", value:"Redis is prone to an ACL bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Redis does not correctly identify keys accessed by SORT_RO and,
  as a result, may grant users executing this command access to keys that are not explicitly
  authorized by the ACL configuration.");

  script_tag(name:"affected", value:"Redis version 7.0.x prior to 7.0.13 and version 7.2.0.");

  script_tag(name:"solution", value:"Update to version 7.0.13, 7.2.1 or later.");

  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-q4jr-5p56-4xwc");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.13");
  security_message(port: port, data: report);
  exit(0);
}

# nb: The first next version after 7.0.x was 7.2.x so there is no need to check for 7.1.x here...
if (version_is_equal(version: version, test_version: "7.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
