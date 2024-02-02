# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:logstash";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126544");
  script_version("2023-11-24T16:09:32+0000");
  script_tag(name:"last_modification", value:"2023-11-24 16:09:32 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-16 10:15:01 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-22 22:38:00 +0000 (Wed, 22 Nov 2023)");

  script_cve_id("CVE-2023-46672");

  # The Logstash version might differ from the Elasticsearch version detected
  # by gb_elastic_elasticsearch_detect_http.nasl
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Logstash 8.10.x < 8.11.1 Information Disclosure Vulnerability (ESA-2023-26)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl");
  script_mandatory_keys("elastic/logstash/detected");

  script_tag(name:"summary", value:"Elastic Logstash is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A sensitive information was recorded in Logstash logs under
  specific circumstances:

  - Logstash is configured to log in JSON format 11, which is not the default logging format.

  - Sensitive data is stored in the Logstash keystore and referenced as a variable in Logstash
    configuration.");

  script_tag(name:"affected", value:"Elastic Logstash version 8.10.x prior to 8.11.1.");

  script_tag(name:"solution", value:"Update to version 8.11.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "8.10.0", test_version_up: "8.11.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.11.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
