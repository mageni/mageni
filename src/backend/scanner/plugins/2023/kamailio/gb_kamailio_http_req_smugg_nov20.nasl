# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:kamailio:kamailio";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170373");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-21 08:35:51 +0000 (Tue, 21 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-03 13:07:00 +0000 (Thu, 03 Dec 2020)");

  script_cve_id("CVE-2020-28361");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kamailio < 5.4.0 Header Smuggling Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_kamailio_sip_detect.nasl");
  script_mandatory_keys("kamailio/detected");

  script_tag(name:"summary", value:"Kamailio is prone to a header smuggling vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Kamailio is often configured to remove certain special internal
  SIP headers from untrusted traffic to protect against header injection attacks by making use of the
  'remove_hf' function from the Kamailio 'textops' module. These SIP headers were typically set
  through Kamailio which are then used downstream, e.g. by a media service based on Asterisk, to
  affect internal business logic decisions. The removal of these headers can be bypassed by injecting
  whitespace characters at the end of the header name.");

  script_tag(name:"impact", value:"The impact of this security bypass greatly depends on how these
  headers are used and processed by the affected logic. In a worst case scenarios, this vulnerability
  could allow toll fraud, caller-ID spoofing and authentication bypass.");

  script_tag(name:"affected", value:"Kamailio prior to version 5.4.0.");

  script_tag(name:"solution", value:"Update to version 5.4.0 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/159030/Kamailio-5.4.0-Header-Smuggling.html");

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

if (version_is_less(version: version, test_version: "5.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.0");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
