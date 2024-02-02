# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114254");
  script_version("2024-02-02T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:11 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-01-10 10:31:13 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 02:22:45 +0000 (Fri, 02 Feb 2024)");

  script_cve_id("CVE-2023-51766");

  # nb: General availability of backports on major Linux distros but also only affected in specific
  # configurations.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim < 4.97.1 SMTP Smuggling Vulnerability (Dec 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("gb_exim_smtp_detect.nasl");
  script_mandatory_keys("exim/detected");

  script_tag(name:"summary", value:"Exim is prone to a SMTP smuggling vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Exim allows SMTP smuggling in certain PIPELINING/CHUNKING
  configurations. Remote attackers can use a published exploitation technique to inject e-mail
  messages with a spoofed MAIL FROM address, allowing bypass of an SPF protection mechanism. This
  occurs because Exim supports <LF>.<CR><LF> but some other popular e-mail servers do not.");

  script_tag(name:"affected", value:"Exim versions prior to 4.97.1.");

  script_tag(name:"solution", value:"Update to version 4.97.1 or later.");

  script_xref(name:"URL", value:"https://exim.org/static/doc/security/CVE-2023-51766.txt");
  script_xref(name:"URL", value:"https://bugs.exim.org/show_bug.cgi?id=3063");
  script_xref(name:"URL", value:"https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/12/21/6");
  script_xref(name:"URL", value:"https://fahrplan.events.ccc.de/congress/2023/fahrplan/events/11782.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.97.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.97.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
