# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170588");
  script_version("2023-11-10T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-11-10 05:05:18 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-09-29 10:21:05 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-07 17:23:00 +0000 (Tue, 07 Nov 2023)");

  script_cve_id("CVE-2023-43339", "CVE-2023-43352", "CVE-2023-43353", "CVE-2023-43354",
                "CVE-2023-43355", "CVE-2023-43356", "CVE-2023-43357", "CVE-2023-43358",
                "CVE-2023-43359", "CVE-2023-43360", "CVE-2023-43872");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("CMS Made Simple <= 2.2.18 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-43339: Multiple reflected cross-site scripting (XSS) vulnerabilities in the
  installation sanitization

  - CVE-2023-43352: Server Side Template Injection (SSTI) vulnerability in the sanitization of the
  entry in the Content of 'Content - Content Manager Menu'

  - CVE-2023-43353: Stored XSS vulnerability in the sanitization of the entry in the Extra of
  'Content - News Menu'

  - CVE-2023-43354: Stored XSS vulnerability in the sanitization of the entry in the Profiles of
  'MicroTiny WYSIWYG editor'

  - CVE-2023-43355: Reflected XSS vulnerability in the sanitization of the entry in the password and
  password of 'My Preferences - Add user.'

  - CVE-2023-43356: Stored XSS vulnerability in the sanitization of the entry in the Global Metadata
  of 'Settings- Global Settings Menu'

  - CVE-2023-43357: Stored XSS vulnerability in the sanitization of the entry in the Title of
  'My Preferences - Manage Shortcuts'

  - CVE-2023-43358: Stored XSS vulnerability in the sanitization of the entry in the Ttile of
  'Content - News Menu'

  - CVE-2023-43359: Stored XSS vulnerability in the sanitization of the entry in the
  'Content Manager Menu'

  - CVE-2023-43360: Stored XSS vulnerability in the sanitization of the entry in the Top Directory
  of 'File Picker Menu'

  - CVE-2023-43872: Stored XSS vulnerability in File Manager file upload sanitization");

  script_tag(name:"affected", value:"CMS Made Simple through version 2.2.18.");

  script_tag(name:"solution", value:"No known solution is available as of 23th October, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/sromanhu/CVE-2023-43339-CMSmadesimple-Reflected-XSS---Installation");
  script_xref(name:"URL", value:"https://github.com/sromanhu/CVE-2023-43352-CMSmadesimple-SSTI--Content");
  script_xref(name:"URL", value:"https://github.com/sromanhu/CVE-2023-43353-CMSmadesimple-Stored-XSS---News---Extra");
  script_xref(name:"URL", value:"https://github.com/sromanhu/CVE-2023-43354-CMSmadesimple-Stored-XSS---MicroTIny-extension");
  script_xref(name:"URL", value:"https://github.com/sromanhu/CVE-2023-43355-CMSmadesimple-Reflected-XSS---Add-user");
  script_xref(name:"URL", value:"https://github.com/sromanhu/CVE-2023-43356-CMSmadesimple-Stored-XSS---Global-Settings");
  script_xref(name:"URL", value:"https://github.com/sromanhu/CVE-2023-43357-CMSmadesimple-Stored-XSS---Shortcut");
  script_xref(name:"URL", value:"https://github.com/sromanhu/CVE-2023-43358-CMSmadesimple-Stored-XSS---News");
  script_xref(name:"URL", value:"https://github.com/sromanhu/CVE-2023-43359-CMSmadesimple-Stored-XSS----Content-Manager");
  script_xref(name:"URL", value:"https://github.com/sromanhu/CVE-2023-43360-CMSmadesimple-Stored-XSS---File-Picker-extension");
  script_xref(name:"URL", value:"https://github.com/sromanhu/CVE-2023-43872-CMSmadesimple-Arbitrary-File-Upload--XSS---File-Manager");

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

if (version_is_less_equal(version: version, test_version: "2.2.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
