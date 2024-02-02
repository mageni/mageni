# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151303");
  script_version("2023-11-24T16:09:32+0000");
  script_tag(name:"last_modification", value:"2023-11-24 16:09:32 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-24 03:16:23 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-21 20:13:00 +0000 (Tue, 21 Nov 2023)");

  script_cve_id("CVE-2023-41570");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS 7.1 < 7.12 Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to an access control vulnerability
  in the REST API.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability lies in the fact that, while other interfaces
  (SSH, Webfig, etc.) check whether the user is authorized to log in from that specific IP address,
  this is not the case for the REST server. Users can access the REST server from any IP address,
  even if they are not authorized in the users database.");

  script_tag(name:"affected", value:"MikroTik RouterOS version 7.1 through 7.11.");

  script_tag(name:"solution", value:"Update to version 7.12 or later.");

  script_xref(name:"URL", value:"https://www.enricobassetti.it/2023/11/cve-2023-41570-access-control-vulnerability-in-mikrotik-rest-api/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.12");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
