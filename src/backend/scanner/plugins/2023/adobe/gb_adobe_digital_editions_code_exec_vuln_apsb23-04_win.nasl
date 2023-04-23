# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826969");
  script_version("2023-04-17T10:09:22+0000");
  script_cve_id("CVE-2023-21582");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-17 10:09:22 +0000 (Mon, 17 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-14 15:30:20 +0530 (Fri, 14 Apr 2023)");
  script_name("Adobe Digital Editions Code Execution Vulnerability (APSB23-04) - Windows");

  script_tag(name:"summary", value:"Adobe Digital Edition is prone to a code
  execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds
  write issue in Adobe Digital Edition.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code on an affected system.");

  script_tag(name:"affected", value:"Adobe Digital Edition versions prior to
  4.5.11.187658.");

  script_tag(name:"solution", value:"Update to Adobe Digital Edition version
  4.5.11.187658 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/Digital-Editions/apsb23-04.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("AdobeDigitalEdition/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");
include("smb_nt.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"4.5.11")){
  vuln = TRUE;
}
else if(version_is_equal(version:vers, test_version:"4.5.11"))
{
  key = "Software\Adobe\Adobe Digital Editions";
  vers = registry_get_sz(key:key, item:"LatestInstalledVersion", type: "HKCU");

  if(vers)
  {
    if(version_is_less(version:vers, test_version:"4.5.11.187658")){
      vuln = TRUE;
    }
  }
}

if( vuln )
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.5.11.187658", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
