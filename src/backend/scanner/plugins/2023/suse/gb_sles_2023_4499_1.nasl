# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4499.1");
  script_cve_id("CVE-2023-38473");
  script_tag(name:"creation_date", value:"2023-11-22 04:22:27 +0000 (Wed, 22 Nov 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 17:46:40 +0000 (Thu, 09 Nov 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4499-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4499-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234499-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'avahi' package(s) announced via the SUSE-SU-2023:4499-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for avahi fixes the following issues:

CVE-2023-38473: Fixed a reachable assertion when parsing a host
 name (bsc#1216419).");

  script_tag(name:"affected", value:"'avahi' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-debuginfo", rpm:"avahi-debuginfo~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-debuginfo-32bit", rpm:"avahi-debuginfo-32bit~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-debugsource", rpm:"avahi-debugsource~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-glib2-debugsource", rpm:"avahi-glib2-debugsource~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-lang", rpm:"avahi-lang~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-utils", rpm:"avahi-utils~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-utils-debuginfo", rpm:"avahi-utils-debuginfo~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-32bit", rpm:"libavahi-client3-32bit~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-debuginfo", rpm:"libavahi-client3-debuginfo~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-debuginfo-32bit", rpm:"libavahi-client3-debuginfo-32bit~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-32bit", rpm:"libavahi-common3-32bit~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-debuginfo", rpm:"libavahi-common3-debuginfo~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-debuginfo-32bit", rpm:"libavahi-common3-debuginfo-32bit~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-core7", rpm:"libavahi-core7~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-core7-debuginfo", rpm:"libavahi-core7-debuginfo~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1-32bit", rpm:"libavahi-glib1-32bit~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1-debuginfo", rpm:"libavahi-glib1-debuginfo~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1-debuginfo-32bit", rpm:"libavahi-glib1-debuginfo-32bit~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd", rpm:"libdns_sd~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd-32bit", rpm:"libdns_sd-32bit~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd-debuginfo", rpm:"libdns_sd-debuginfo~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd-debuginfo-32bit", rpm:"libdns_sd-debuginfo-32bit~0.6.32~32.21.1", rls:"SLES12.0SP5"))) {
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
