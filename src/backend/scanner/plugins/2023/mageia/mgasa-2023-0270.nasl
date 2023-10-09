# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0270");
  script_cve_id("CVE-2023-4527", "CVE-2023-4806");
  script_tag(name:"creation_date", value:"2023-09-28 04:11:56 +0000 (Thu, 28 Sep 2023)");
  script_version("2023-09-29T16:09:25+0000");
  script_tag(name:"last_modification", value:"2023-09-29 16:09:25 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-22 17:52:00 +0000 (Fri, 22 Sep 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0270)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0270");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0270.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32292");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the MGASA-2023-0270 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"getaddrinfo: Fix use after free in getcanonname (CVE-2023-4806)

Stack read overflow with large TCP responses in no-aaaa mode
(CVE-2023-4527)

elf: Introduce to _dl_call_fini
elf: Do not run constructors for proxy objects
elf: Always call destructors in reverse constructor order [BZ #30785]
elf: Remove unused l_text_end field from struct link_map
elf: Move l_init_called_next to old place of l_text_end in link map
elf: Fix slow tls access after dlopen [BZ #19924]
intl: Treat C.UTF-8 locale like C locale [BZ# 16621]
x86: Increase non_temporal_threshold to roughly 'sizeof_L3 / 4'
x86: Fix slight bug in shared_per_thread cache size calculation
x86: Use 3/4*sizeof(per-thread-L3) as low bound for NT threshold
x86: Fix incorrect scope of setting shared_per_thread [BZ #30745]");

  script_tag(name:"affected", value:"'glibc' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.36~49.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.36~49.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.36~49.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.36~49.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.36~49.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.36~49.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.36~49.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.36~49.mga9", rls:"MAGEIA9"))) {
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
