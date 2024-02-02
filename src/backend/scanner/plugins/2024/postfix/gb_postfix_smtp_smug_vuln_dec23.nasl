# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postfix:postfix";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114255");
  script_version("2024-01-12T05:05:56+0000");
  script_tag(name:"last_modification", value:"2024-01-12 05:05:56 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-10 10:31:13 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-05 16:19:00 +0000 (Fri, 05 Jan 2024)");

  script_cve_id("CVE-2023-51764");

  # nb: General availability of backports on major Linux distros but also only affected in specific
  # configurations.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Postfix SMTP Smuggling Vulnerability (Dec 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("sw_postfix_smtp_detect.nasl");
  script_mandatory_keys("postfix/smtp/detected");

  script_tag(name:"summary", value:"Postfix is prone to a SMTP smuggling vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Postfix allows SMTP smuggling unless configured with
  smtpd_data_restrictions=reject_unauth_pipelining and smtpd_discard_ehlo_keywords=chunking (or
  certain other options that exist in recent versions). Remote attackers can use a published
  exploitation technique to inject e-mail messages with a spoofed MAIL FROM address, allowing bypass
  of an SPF protection mechanism. This occurs because Postfix supports <LF>.<CR><LF> but some other
  popular e-mail servers do not. To prevent attack variants (by always disallowing <LF> without
  <CR>), a different solution is required: the smtpd_forbid_bare_newline=yes option with a Postfix
  minimum version of 3.5.23, 3.6.13, 3.7.9, 3.8.4, or 3.9.");

  script_tag(name:"affected", value:"Postfix versions through 3.8.4.");

  script_tag(name:"solution", value:"Update to version 3.5.23, 3.6.13, 3.7.9, 3.8.4, 3.9 or later
  and set the option mentioned by the vendor within the Postfix configuration.");

  script_xref(name:"URL", value:"https://www.postfix.org/smtp-smuggling.html");
  script_xref(name:"URL", value:"https://www.postfix.org/false-smuggling-claims.html");
  script_xref(name:"URL", value:"https://www.postfix.org/announcements/postfix-3.8.4.html");
  script_xref(name:"URL", value:"https://www.postfix.org/announcements/postfix-3.7.9.html");
  script_xref(name:"URL", value:"https://www.postfix.org/announcements/postfix-3.6.13.html");
  script_xref(name:"URL", value:"https://www.postfix.org/announcements/postfix-3.5.23.html");
  script_xref(name:"URL", value:"https://www.mail-archive.com/postfix-users@postfix.org/msg100901.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255563");
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

if (version_is_less(version: version, test_version: "3.5.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.23");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.6", test_version_up: "3.6.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.13");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.7", test_version_up: "3.7.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.9");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.8", test_version_up: "3.8.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
