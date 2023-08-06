# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0232");
  script_cve_id("CVE-2021-32055", "CVE-2022-1328");
  script_tag(name:"creation_date", value:"2023-07-20 04:12:53 +0000 (Thu, 20 Jul 2023)");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-01 14:52:00 +0000 (Tue, 01 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2023-0232)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0232");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0232.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30292");
  script_xref(name:"URL", value:"https://marc.info/?l=mutt-users&m=164979464612885&w=2");
  script_xref(name:"URL", value:"https://gitlab.com/muttmua/mutt/-/issues/404");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DR7ZSOKFQZ5EIKQHLZ37AMGVPDGDIJ5W/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5392-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/35CD7NH4NFPF5OEG2PHI3CZ3UOK3ICXR/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YAIJ2AOB7KV4ZEDS2ZHBBCKGSPYKSKDI/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mutt, neomutt' package(s) announced via the MGASA-2023-0232 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Out-of-bounds read in imap/util.c when an IMAP sequence set ends with a
comma. (CVE-2021-32055)
Overflow in uudecoder in Mutt allows read past end of input line
(CVE-2022-1328)");

  script_tag(name:"affected", value:"'mutt, neomutt' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"mutt", rpm:"mutt~2.0.7~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutt-doc", rpm:"mutt-doc~2.0.7~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neomutt", rpm:"neomutt~20230517~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neomutt-doc", rpm:"neomutt-doc~20230517~1.mga8", rls:"MAGEIA8"))) {
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
