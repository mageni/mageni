# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0238");
  script_cve_id("CVE-2023-3338", "CVE-2023-3390");
  script_tag(name:"creation_date", value:"2023-07-20 04:12:53 +0000 (Thu, 20 Jul 2023)");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-06 21:32:00 +0000 (Thu, 06 Jul 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0238)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0238");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0238.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32094");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31982");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.118");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.119");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.120");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2023-0238 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.15.120 and fixes at least
the following security issues:

A flaw null pointer dereference in the Linux kernel DECnet networking
protocol was found. A remote user could use this flaw to crash the
system. This is fixed by removing DECnet support (CVE-2023-3338).

A use-after-free vulnerability was found in the Linux kernel's netfilter
subsystem in net/netfilter/nf_tables_api.c. Mishandled error handling with
NFT_MSG_NEWRULE makes it possible to use a dangling pointer in the same
transaction causing a use-after-free vulnerability. This flaw allows a
local attacker with user access to cause a privilege escalation issue
(CVE-2023-3390).

NOTE!!
This kernel also contains a fix for dkms builds hanging / stalling during
upgrade to Mageia 9 (mga#31982) due to the new make 4.4 series utility
ending up in a loop processing Makefile in kernel-devel packages.
So if you use dkms packaged drivers and kernel-linus, you need to be
running this kernel (or any later released ones) before you do an online
upgrade to avoid the upgrade stalling / hanging.

For other upstream fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.120-2.mga8", rpm:"kernel-linus-5.15.120-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.120~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.120-2.mga8", rpm:"kernel-linus-devel-5.15.120-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.120~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.120~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.120~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.120-2.mga8", rpm:"kernel-linus-source-5.15.120-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.120~2.mga8", rls:"MAGEIA8"))) {
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
