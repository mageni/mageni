# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redhat:wildfly";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126501");
  script_version("2023-10-06T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-18 09:00:19 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-10 18:10:00 +0000 (Fri, 10 Jul 2020)");

  script_cve_id("CVE-2020-10740", "CVE-2020-1719");

  # nb: No "remote_banner_unreliable" as the VT is checking for < 20 which is fine (the HTTP
  # detection is only able to extract the major version like e.g. "26").
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Red Hat WildFly < 20.0.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("sw_redhat_wildfly_http_detect.nasl");
  script_mandatory_keys("redhat/wildfly/detected");

  script_tag(name:"summary", value:"Red Hat WildFly is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-10740: A remote deserialization attack is possible in the Enterprise Application Beans
  (EJB) due to lack of validation/filtering capabilities in wildfly.orf.

  - CVE-2020-1719: The EJBContext principle is not popped back after invoking another EJB using a
  different Security Domain. The highest threat from this vulnerability is to data confidentiality
  and integrity.");

  script_tag(name:"affected", value:"Red Hat WildFly prior to version 20.0.0.");

  script_tag(name:"solution", value:"Update to version 20.0.0 or later.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-10740");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-1719");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

# nb: We're just using "20" here because the HTTP detection is currently only extracting versions
# like e.g. "20", "26" and so on.
if (version_is_less(version: version, test_version: "20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
