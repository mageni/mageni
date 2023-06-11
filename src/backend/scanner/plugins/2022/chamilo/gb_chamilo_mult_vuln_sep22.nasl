# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127209");
  script_version("2023-06-01T09:09:48+0000");
  script_tag(name:"last_modification", value:"2023-06-01 09:09:48 +0000 (Thu, 01 Jun 2023)");
  script_tag(name:"creation_date", value:"2022-10-03 08:47:25 +0000 (Mon, 03 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-25 13:45:00 +0000 (Mon, 25 Apr 2022)");

  script_cve_id("CVE-2022-27422", "CVE-2022-27423", "CVE-2022-27425");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Chamilo LMS <= 1.11.16 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-27422: An attacker is able to execute arbitrary web scripts or HTML via user
  interaction with a crafted URL.

  - CVE-2022-27423: The /blog/blog.php component contains SQL injection vulnerability.

  - CVE-2022-27425: The blog_id parameter at /blog/blog.php contains XSS (Cross-Site Scitpting)
  vulnerability.");

  # nb: It wasn't possible to match any of the CVE description to the security issues described
  # on the security issue page so a version <= 1.11.16 as defined within the NVD was used.
  script_tag(name:"affected", value:"Chamilo LMS versions 1.11.16 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues");

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

if (version_is_less_equal(version: version, test_version: "1.11.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
