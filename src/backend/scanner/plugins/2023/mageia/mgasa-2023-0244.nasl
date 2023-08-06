# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0244");
  script_cve_id("CVE-2023-20593");
  script_tag(name:"creation_date", value:"2023-07-27 04:12:36 +0000 (Thu, 27 Jul 2023)");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 19:29:00 +0000 (Tue, 01 Aug 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0244)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0244");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0244.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32142");
  script_xref(name:"URL", value:"https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7008.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2023-0244 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Under specific microarchitectural circumstances, a register in 'Zen 2'
CPUs may not be written to 0 correctly. This may cause data from another
process and/or thread to be stored in the YMM register, which may allow
an attacker to potentially access sensitive information (CVE-2023-20593,
also known as Zenbleed).

This update adds the microcode for Amd Epyc gen 2 cpus. Other Zen 2 based
CPUs will get their microcode update at a later time when Amd has fixed
and validated the microcodes, see the referenced Amd url that has info
about estimated timelines for various CPUs.");

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

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20230613~2.mga8.nonfree", rls:"MAGEIA8"))) {
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
