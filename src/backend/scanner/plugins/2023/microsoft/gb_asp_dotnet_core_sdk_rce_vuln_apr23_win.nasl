# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:microsoft:.netcore_sdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826963");
  script_version("2023-04-13T10:09:33+0000");
  script_cve_id("CVE-2023-28260");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-04-13 10:09:33 +0000 (Thu, 13 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-12 14:55:27 +0530 (Wed, 12 Apr 2023)");
  script_name(".NET Core SDK Remote Code Execution Vulnerability - Apr23");

  script_tag(name:"summary", value:"ASP.NET Core SDK is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified error in
  the Microsoft ASP.NET Core SDK");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution on the affected system.");

  script_tag(name:"affected", value:"ASP.NET Core SDK 6.0.x prior to 6.0.408 version
  and 7.0.x prior to 7.0.203");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the
  references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://dotnet.microsoft.com/en-us/download/dotnet/7.0");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28260");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys(".NET/Core/SDK/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
coreVers = infos['version'];
path = infos['location'];

if (coreVers =~ "^7\.0" && version_is_less(version:coreVers, test_version:"7.0.203")){
  fix = "7.0.203";
}

else if (coreVers =~ "^6\.0" && version_is_less(version:coreVers, test_version:"6.0.408")){
  fix = "6.0.408" ;
}

if(fix)
{
  report = report_fixed_ver(installed_version:coreVers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
