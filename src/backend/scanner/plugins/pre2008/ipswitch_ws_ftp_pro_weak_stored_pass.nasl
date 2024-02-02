# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ipswitch:ws_ftp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14597");
  script_version("2023-12-01T05:05:39+0000");
  script_cve_id("CVE-1999-1078");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ipswitch WS_FTP Professional < 12.6 Weak Stored Password Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("gb_ipswitch_ws_ftp_pro_smb_login_detect.nasl");
  script_mandatory_keys("ipswitch/ws_ftp/professional/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210129173743/https://www.securityfocus.com/bid/547/");

  script_tag(name:"summary", value:"Ipswitch WS_FTP Professional is using a weak encryption method
  to store site passwords.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Ipswitch WS_FTP Professional versions 2006 through 2007.0.0.2
  are known to be affected.");

  script_tag(name:"solution", value:"Update to version 12.6 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

# nb: About the versions:
# - Version 2006 and 2007 existed initially
# - After 2007 version 12.4 started (up to the recent 12.9)
# - We can't use version_is_less() here as we would cause a false positive for 12.x versions
if(version_in_range(version:version, test_version:"2006", test_version2:"2007.0.0.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.6", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
