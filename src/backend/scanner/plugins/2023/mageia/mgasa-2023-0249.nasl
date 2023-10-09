# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0249");
  script_cve_id("CVE-2022-40982", "CVE-2022-41804", "CVE-2023-20569", "CVE-2023-23908");
  script_tag(name:"creation_date", value:"2023-08-24 04:11:47 +0000 (Thu, 24 Aug 2023)");
  script_version("2023-09-20T05:05:13+0000");
  script_tag(name:"last_modification", value:"2023-09-20 05:05:13 +0000 (Wed, 20 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-18 03:15:00 +0000 (Fri, 18 Aug 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0249)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0249");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0249.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32167");
  script_xref(name:"URL", value:"https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7005.html");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/releases/tag/microcode-20230808");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00828.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00836.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00837.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2023-0249 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update adds initial microcode updates for AMD and Intel CPUs for the
following security issues:


AMD:
A side channel vulnerability in some of the AMD CPUs may allow an attacker
to influence the return address prediction. This may result in speculative
execution at an attacker-controlled instruction pointer register,
potentially leading to information disclosure (CVE-2023-20569).


Intel:
Information exposure through microarchitectural state after transient
execution in certain vector execution units for some Intel(R) Processors
may allow an authenticated user to potentially enable information disclosure
via local access (CVE-2022-40982, INTEL-SA-00828).

Unauthorized error injection in Intel(R) SGX or Intel(R) TDX for some
Intel(R) Xeon(R) Processors may allow a privileged user to potentially
enable escalation of privilege via local access (CVE-2022-41804,
INTEL-SA-00837).

Improper access control in some 3rd Generation Intel(R) Xeon(R) Scalable
processors may allow a privileged user to potentially enable information
disclosure via local access (CVE-2023-23908, INTEL-SA-00836).");

  script_tag(name:"affected", value:"'microcode' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20230808~2.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
