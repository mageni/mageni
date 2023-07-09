# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104818");
  script_version("2023-06-28T05:05:22+0000");
  script_tag(name:"creation_date", value:"2023-06-26 13:33:51 +0000 (Mon, 26 Jun 2023)");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:22 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-19 06:22:00 +0000 (Sun, 19 Feb 2017)");

  script_cve_id("CVE-2016-7152", "CVE-2016-7153");

  script_name("Mozilla Firefox 'HEIST' Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl", "gb_firefox_detect_win.nasl",
                      "gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("mozilla/firefox/detected");

  script_xref(name:"URL", value:"https://www.blackhat.com/docs/us-16/materials/us-16-VanGoethem-HEIST-HTTP-Encrypted-Information-Can-Be-Stolen-Through-TCP-Windows-wp.pdf");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1388003");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1388005");
  script_xref(name:"URL", value:"https://support.mozilla.org/en-US/kb/third-party-cookies-firefox-tracking-protection");

  script_tag(name:"summary", value:"Mozilla Firefox might be prone to multiple vulnerabilities
  dubbed 'HEIST'.");

  script_tag(name:"vuldetect", value:"Reports if Mozilla Firefox is installed on the target.");

  script_tag(name:"insight", value:"HEIST enables an attacker to conduct BREACH attack against HTTP
  compression and CRIME attack against TLS compression without being in a man-in-the-middle
  position. HEIST uses a side-channel attack involving TCP-windows to leak the exact size of any
  cross-origin response, without having to observe traffic at the network level. Thus, HEIST enables
  compression-based attacks such as CRIME and BREACH to be performed purely in the browser, by any
  malicious website or script, without requiring a man-in-the-middle position.

  HEIST stands for 'HTTP Encrypted Information can be Stolen through TCP-windows'.");

  script_tag(name:"affected", value:"Mozilla Firefox when using a web-browser configuration in which
  third-party cookies are sent.");

  script_tag(name:"solution", value:"Make sure to disable third-party cookies in the browser. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:FALSE))
  exit(0);

version = infos["version"];
location = infos["location"];

report = report_fixed_ver(installed_version:version, fixed_version:"None, see the references for mitigation steps.", install_path:location);
security_message(port:0, data:report);

exit(0); # nb: No exit(99); on purpose...
