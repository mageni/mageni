# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127227");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2022-10-24 10:11:43 +0000 (Mon, 24 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-19 13:34:00 +0000 (Wed, 19 Oct 2022)");

  script_cve_id("CVE-2022-28291");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Tenable Nessus Information Disclosure Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("tenable/nessus/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Tenable Nessus on Windows is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can retrieve stored credentials in Nessus Policies
  in cleartext from the 'nessusd' process.");

  script_tag(name:"affected", value:"All versions of Tenable Nessus on Windows.

  Note: The vendor deems the issue as acceptable risk and will not provide a fix. Please see the
  references for more information.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://www.securin.io/articles/securin-expert-discovers-a-zero-day-vulnerability-in-tenables-nessus-scanner/");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
security_message(data:report, port:port);
exit(0);
