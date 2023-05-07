# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149631");
  script_version("2023-05-04T09:51:03+0000");
  script_tag(name:"last_modification", value:"2023-05-04 09:51:03 +0000 (Thu, 04 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-04 04:47:10 +0000 (Thu, 04 May 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2023-31414");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana 8.0.0 - 8.7.0 Arbitrary Code Execution Vulnerability (ESA-2023-07)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_elastic_kibana_detect_http.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Kibana is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker with write access to Kibana yaml or env
  configuration could add a specific payload that will attempt to execute JavaScript code. This
  could lead to the attacker executing arbitrary commands on the host system with permissions of
  the Kibana process.

  Note:

  - This issue does not affect Kibana instances running on Elastic Cloud as the payload required to
  trigger this vulnerability cannot be set in Kibana's configuration.

  - This issue affects Kibana instances running on Elastic Cloud Enterprise (ECE) but the code
  execution is limited within the Kibana Docker container. Further exploitation such as container
  escape is prevented by seccomp-bpf and AppArmor profiles.

  - This issue affects Kibana instances running on Elastic Cloud on Kubernetes (ECK) but the code
  execution is limited within the Kibana Docker container. Further exploitation such as container
  escape can be prevented by seccomp-bpf when configured and supported (Kubernetes v1.19 and
  later).");

  script_tag(name:"affected", value:"Kibana version 8.0.0 through 8.7.0.");

  script_tag(name:"solution", value:"Update to version 8.7.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/kibana-8-7-1-security-updates/332330");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0", test_version_up: "8.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
