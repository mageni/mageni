# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:kamailio:kamailio";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170372");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-21 08:35:51 +0000 (Tue, 21 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2020-27507");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kamailio < 5.5.0 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_kamailio_sip_detect.nasl");
  script_mandatory_keys("kamailio/detected");

  script_tag(name:"summary", value:"Kamailio is prone to a buffer overflow vulnerability which may
  result in a crash of the server.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Kamailio SIP server mishandles INVITE requests with duplicated
  fields and overlength tag.");

  script_tag(name:"impact", value:"Abuse of this vulnerability leads to a crash of the server or
  possibly have unspecified other impact.");

  script_tag(name:"affected", value:"Kamailio prior to version 5.5.0.");

  script_tag(name:"solution", value:"Update to version 5.5.0 or later.");

  script_xref(name:"URL", value:"https://github.com/kamailio/kamailio/issues/2503");
  script_xref(name:"URL", value:"https://github.com/kamailio/kamailio/commit/ada3701d22b1fd579f06b4f54fa695fa988e685f");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "5.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.0");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
