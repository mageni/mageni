# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:emby:emby.releases";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149863");
  script_version("2023-06-30T16:09:17+0000");
  script_tag(name:"last_modification", value:"2023-06-30 16:09:17 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-30 03:58:48 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2021-25827", "CVE-2023-33193");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Emby Server Proxy Header Spoofing Vulnerability (GHSA-fffj-6fr6-3fgf)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_emby_server_http_detect.nasl");
  script_mandatory_keys("emby/media_server/detected");

  script_tag(name:"summary", value:"Emby Server is prone to a proxy header spoofing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Login bypass attack by setting the X-Forwarded-For header to
  a local IP-address.");

  script_tag(name:"impact", value:"This vulnerability may allow administrative access to an Emby
  Server system, depending on certain user account settings. Emby server employs a determination of
  'Local Network' vs. 'Non-Local Network' depending on connection parameters of a remote request.
  This determination in turn, may affect the behavior of certain features and also the requirements
  regarding account logins.
  By spoofing certain headers which are intended for interoperation with reverse proxy servers, it
  may be possible to affect the local/non-local network determination to allow logging in without
  password or to view a list of user accounts which may have no password configured.");

  script_tag(name:"affected", value:"Emby Server version 4.7.11 and prior and version 4.8.x through
  4.8.0.30.");

  script_tag(name:"solution", value:"Update to version 4.7.12, 4.8.0.31 or later.");

  script_xref(name:"URL", value:"https://github.com/EmbySupport/security/security/advisories/GHSA-fffj-6fr6-3fgf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.7.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.8.0", test_version_up: "4.8.0.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.0.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
