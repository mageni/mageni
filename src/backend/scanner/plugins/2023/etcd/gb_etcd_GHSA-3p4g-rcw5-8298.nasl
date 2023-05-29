# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:etcd:etcd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149673");
  script_version("2023-05-16T09:08:27+0000");
  script_tag(name:"last_modification", value:"2023-05-16 09:08:27 +0000 (Tue, 16 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-15 06:58:25 +0000 (Mon, 15 May 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2023-32082");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("etcd < 3.4.26, 3.5.x < 3.5.9 Information Disclosure Vulnerability (GHSA-3p4g-rcw5-8298)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_etcd_http_detect.nasl");
  script_mandatory_keys("etcd/detected");

  script_tag(name:"summary", value:"etcd is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"LeaseTimeToLive API allows access to key names (not value)
  associated to a lease when Keys parameter is true, even a user doesn't have read permission to
  the keys. The impact is limited to a cluster which enables auth (RBAC).");

  script_tag(name:"affected", value:"etcd prior to version 3.4.26 and version 3.5.x through 3.5.8.");

  script_tag(name:"solution", value:"Update to version 3.4.26, 3.5.9 or later.");

  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/security/advisories/GHSA-3p4g-rcw5-8298");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.4.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.26");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.5", test_version_up: "3.5.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.9");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
