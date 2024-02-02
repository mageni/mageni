# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832644");
  script_version("2023-12-14T08:20:35+0000");
  script_cve_id("CVE-2023-36010");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-12-14 08:20:35 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 18:58:00 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-13 11:16:35 +0530 (Wed, 13 Dec 2023)");
  script_name("Microsoft Security Essentials DoS Vulnerability - Dec 2023");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Security Updates released for Microsoft Security
  Essentials Protection Engine dated 13-12-2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host");

  script_tag(name:"insight", value:"The flaw exists due to a denial of service
  vulnerability in Microsoft Security Essentials");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause denial of service on an affected system.");

  script_tag(name:"affected", value:"Microsoft Security Essentials prior to Engine version 1.1.23110.2.");

  script_tag(name:"solution", value:"Run the Windows Update to update the malware
  protection engine to the latest version available. Typically, no action is
  required as the built-in mechanism for the automatic detection and deployment
  of updates will apply the update itself.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36010");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");

key = "SOFTWARE\Microsoft\Microsoft Antimalware";
if(!registry_key_exists(key:key)) {
  exit(0);
}

def_version = registry_get_sz(key:"SOFTWARE\Microsoft\Microsoft Antimalware\Signature Updates",
                              item:"EngineVersion");
if(!def_version) {
  exit(0);
}

if(version_is_less(version:def_version, test_version:"1.1.23110.2")) {
  report = report_fixed_ver(installed_version:def_version, fixed_version: "1.1.23110.2 or higher");
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
