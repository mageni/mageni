# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114176");
  script_version("2023-11-21T05:05:52+0000");
  script_tag(name:"last_modification", value:"2023-11-21 05:05:52 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-16 15:34:29 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Tenable Nessus End of Life (EOL) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_xref(name:"URL", value:"https://docs.tenable.com/PDFs/product-lifecycle-management/tenable-software-release-lifecycle-matrix.pdf");

  script_tag(name:"summary", value:"The Tenable Nessus version on the remote host has reached the
  End of Life (EOL) and should not be used anymore.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"impact", value:"An EOL version of Tenable Nessus is not receiving any security
  updates from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to
  compromise the security of this host.");

  script_tag(name:"solution", value:"Update the Tenable Nessus version on the remote host to a still
  supported version.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("products_eol.inc");
include("list_array_func.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];

if (ret = product_reached_eol(cpe: CPE, version: version)) {
  report = build_eol_message(name: "Tenable Nessus",
                             cpe: CPE,
                             version: version,
                             location: infos["location"],
                             eol_version: ret["eol_version"],
                             eol_date: ret["eol_date"],
                             eol_type: "prod");
  security_message(port: port, data: report);
  exit(0);
}

# nb: Special handling for versions below 8.14.0 as the vendor had only included versions up to
# 8.14.x in the linked PDF and there is an unknown amount of other versions which would make the
# array in products_eol.inc too big...

if (version_is_less(version: version, test_version: "8.14.0")) {
  report = build_eol_message(name: "Tenable Nessus",
                             cpe: CPE,
                             version: version,
                             location: infos["location"],
                             eol_version: "8.x or prior",
                             eol_date: "unknown",
                             eol_type: "prod");
  security_message(port: port, data: report);
  exit(0);
}


exit(99);
