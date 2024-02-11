# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0033");
  script_cve_id("CVE-2023-46838", "CVE-2023-6610");
  script_tag(name:"creation_date", value:"2024-02-09 04:12:12 +0000 (Fri, 09 Feb 2024)");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 02:06:40 +0000 (Fri, 02 Feb 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0033)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0033");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0033.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32786");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.1");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.2");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.3");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.4");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.5");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.6");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.7");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.8");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.9");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.10");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.11");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.12");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.13");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.14");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-448.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-applets, kernel, kmod-virtualbox, kmod-xtables-addons, mate-applets' package(s) announced via the MGASA-2024-0033 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Upstream version 6.6.14 with many bugfixes and at least the following
security fixes:
An out-of-bounds read vulnerability was found in smb2_dump_detail in
fs/smb/client/smb2ops.c in the Linux Kernel. This issue could allow a
local attacker to crash the system or leak internal kernel information.
(CVE-2023-6610)
An unprivileged guest can cause Denial of Service (DoS) of the host by
sending network packets to the backend, causing the backend to crash.
Data corruption or privilege escalation have not been ruled out.
[link moved to references] (CVE-2023-46838)");

  script_tag(name:"affected", value:"'gnome-applets, kernel, kmod-virtualbox, kmod-xtables-addons, mate-applets' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-applets", rpm:"gnome-applets~3.46.0~3.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop", rpm:"kernel-desktop~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel", rpm:"kernel-desktop-devel~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586", rpm:"kernel-desktop586~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel", rpm:"kernel-desktop586-devel~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server", rpm:"kernel-server~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel", rpm:"kernel-server-devel~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~7.0.14~42.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.24~54.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf1", rpm:"lib64bpf1~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf1", rpm:"libbpf1~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mate-applets", rpm:"mate-applets~1.26.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~6.6.14~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-6.6.14-desktop-2.mga9", rpm:"virtualbox-kernel-6.6.14-desktop-2.mga9~7.0.14~42.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-6.6.14-server-2.mga9", rpm:"virtualbox-kernel-6.6.14-server-2.mga9~7.0.14~42.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~7.0.14~42.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~7.0.14~42.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-6.6.14-desktop-2.mga9", rpm:"xtables-addons-kernel-6.6.14-desktop-2.mga9~3.24~54.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-6.6.14-desktop586-2.mga9", rpm:"xtables-addons-kernel-6.6.14-desktop586-2.mga9~3.24~54.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-6.6.14-server-2.mga9", rpm:"xtables-addons-kernel-6.6.14-server-2.mga9~3.24~54.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.24~54.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.24~54.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.24~54.mga9", rls:"MAGEIA9"))) {
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
