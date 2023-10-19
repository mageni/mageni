# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832537");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2023-36720", "CVE-2023-36724", "CVE-2023-36725", "CVE-2023-36434",
                "CVE-2023-36438", "CVE-2023-36570", "CVE-2023-36731", "CVE-2023-36557",
                "CVE-2023-36602", "CVE-2023-44487", "CVE-2023-36563", "CVE-2023-36717",
                "CVE-2023-36722", "CVE-2023-36436", "CVE-2023-36431", "CVE-2023-36598",
                "CVE-2023-36721", "CVE-2023-36726", "CVE-2023-36576", "CVE-2023-36718",
                "CVE-2023-36723", "CVE-2023-36732", "CVE-2023-41773", "CVE-2023-41772",
                "CVE-2023-41771", "CVE-2023-41770", "CVE-2023-41768", "CVE-2023-41767",
                "CVE-2023-36743", "CVE-2023-36776", "CVE-2023-38166", "CVE-2023-38171",
                "CVE-2023-36435", "CVE-2023-36902", "CVE-2023-35349", "CVE-2023-36564",
                "CVE-2023-36567", "CVE-2023-36571", "CVE-2023-36572", "CVE-2023-36573",
                "CVE-2023-36574", "CVE-2023-36575", "CVE-2023-36577", "CVE-2023-36578",
                "CVE-2023-36579", "CVE-2023-36581", "CVE-2023-36582", "CVE-2023-36583",
                "CVE-2023-36584", "CVE-2023-36585", "CVE-2023-36589", "CVE-2023-36590",
                "CVE-2023-36591", "CVE-2023-36592", "CVE-2023-36593", "CVE-2023-36594",
                "CVE-2023-36596", "CVE-2023-36603", "CVE-2023-36605", "CVE-2023-36606",
                "CVE-2023-36697", "CVE-2023-36698", "CVE-2023-36701", "CVE-2023-36702",
                "CVE-2023-36709", "CVE-2023-36710", "CVE-2023-36711", "CVE-2023-36712",
                "CVE-2023-36713", "CVE-2023-36729", "CVE-2023-41774", "CVE-2023-41769",
                "CVE-2023-41766", "CVE-2023-41765", "CVE-2023-38159");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-10 18:21:00 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-11 09:51:00 +0530 (Wed, 11 Oct 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5031354)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5031354");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An Information Disclosure Vulnerability in Active Directory Domain Services.

  - An Elevation of Privilege Vulnerability in Win32k.

  - A Remote Code Execution Vulnerability in Layer 2 Tunneling Protocol.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information, bypass security restrictions, and conduct DoS
  attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 11 Version 22H2 for x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5031354");
  script_xref(name:"URL", value:"https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack");
  script_xref(name:"URL", value:"https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/");
  script_xref(name:"URL", value:"https://aws.amazon.com/blogs/security/how-aws-protects-customers-from-ddos-events/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/10/6");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win11:1) <= 0) {
  exit(0);
}

dllPath = smb_get_systemroot();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"\system32\user32.dll");
if(!fileVer) {
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.22621.0", test_version2:"10.0.22621.2427")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\user32.dll", file_version:fileVer, vulnerable_range:"10.0.22621.0 - 10.0.22621.2427");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
