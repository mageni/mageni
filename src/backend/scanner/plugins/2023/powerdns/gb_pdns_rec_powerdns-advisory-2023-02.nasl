# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149470");
  script_version("2023-03-31T10:08:38+0000");
  script_tag(name:"last_modification", value:"2023-03-31 10:08:38 +0000 (Fri, 31 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-31 03:31:48 +0000 (Fri, 31 Mar 2023)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2023-26437");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor DoS Vulnerability (2023-02)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When the recursor detects and deters a spoofing attempt or
  receives certain malformed DNS packets, it throttles the server that was the target of the
  impersonation attempt so that other authoritative servers for the same zone will be more likely
  to be used in the future, in case the attacker controls the path to one server only.
  Unfortunately this mechanism can be used by an attacker with the ability to send queries to the
  recursor, guess the correct source port of the corresponding outgoing query and inject packets
  with a spoofed IP address to force the recursor to mark specific authoritative servers as not
  available, leading a denial of service for the zones served by those servers.");

  script_tag(name:"affected", value:"PowerDNS Recursor version 4.6.5 and prior, 4.7.x through 4.7.4
  and 4.8.x through 4.8.3.");

  script_tag(name:"solution", value:"Update to version 4.6.6, 4.7.5, 4.8.4 or later.");

  script_xref(name:"URL", value:"https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2023-02.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "4.6.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.6");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.7.0", test_version2: "4.7.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.5");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.8.0", test_version2: "4.8.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.4");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
