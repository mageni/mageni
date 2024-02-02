# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:huawei:cloudengine_1800v_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151443");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-21 06:49:00 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-28 17:35:00 +0000 (Mon, 28 Dec 2020)");

  script_cve_id("CVE-2020-9120");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Resource Management Error Vulnerability in Huawei CloudEngine 1800V Product (huawei-sa-20201202-01-cloudengine)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"CloudEngine 1800V product has a resource management error
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote unauthorized attackers could send specific types of
  messages to the device, resulting in the message received by the system can't be forwarded
  normally.");

  script_tag(name:"affected", value:"CloudEngine 1800V version V100R019C10SPC500.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20201202-01-cloudengine-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = toupper(version);

if (version =~ "^V100R019C10SPC500") {
  report = report_fixed_ver(installed_version: version, fixed_version: "V100R019C10SPC800");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
