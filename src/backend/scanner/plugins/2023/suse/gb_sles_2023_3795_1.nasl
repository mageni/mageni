# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3795.1");
  script_cve_id("CVE-2023-20900");
  script_tag(name:"creation_date", value:"2023-09-27 04:21:57 +0000 (Wed, 27 Sep 2023)");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-06 13:37:00 +0000 (Wed, 06 Sep 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3795-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3795-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233795-1/");
  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2023-0019.html");
  script_xref(name:"URL", value:"https://github.com/vmware/open-vm-tools/releases/tag/stable-12.3.0");
  script_xref(name:"URL", value:"https://github.com/vmware/open-vm-tools/blob/stable-12.3.0/ReleaseNotes.md");
  script_xref(name:"URL", value:"https://github.com/vmware/open-vm-tools/blob/stable-12.3.0/open-vm-tools/ChangeLog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open-vm-tools' package(s) announced via the SUSE-SU-2023:3795-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for open-vm-tools fixes the following issues:
Update to 12.3.0 (build 22234872) (bsc#1214850)

There are no new features in the open-vm-tools 12.3.0 release. This is
 primarily a maintenance release that addresses a few critical problems,
 including:
This release integrates CVE-2023-20900 without the need for a patch.
 For more information on this vulnerability and its impact on VMware
 products, see
 [link moved to references].
A tools.conf configuration setting is available to temporaily direct
 Linux quiesced snaphots to restore pre open-vm-tools 12.2.0 behavior
 of ignoring file systems already frozen.
Building of the VMware Guest Authentication Service (VGAuth) using
 'xml-security-c' and 'xerces-c' is being deprecated.
A number of Coverity reported issues have been addressed.
A number of GitHub issues and pull requests have been handled.
 Please see the Resolves Issues section of the Release Notes.
For issues resolved in this release, see the Resolved Issues section
 of the Release Notes.
For complete details, see:
 [link moved to references] Release Notes are available at
 [link moved to references] The granular changes that have gone into the 12.3.0 release are in the
 ChangeLog at
 [link moved to references] Fix (bsc#1205927) - hv_vmbus module is loaded unnecessarily in VMware guests jsc#PED-1344 - reinable building containerinfo plugin for SLES 15 SP4.");

  script_tag(name:"affected", value:"'open-vm-tools' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~12.3.0~4.59.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0-debuginfo", rpm:"libvmtools0-debuginfo~12.3.0~4.59.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~12.3.0~4.59.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debuginfo", rpm:"open-vm-tools-debuginfo~12.3.0~4.59.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-debugsource", rpm:"open-vm-tools-debugsource~12.3.0~4.59.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~12.3.0~4.59.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop-debuginfo", rpm:"open-vm-tools-desktop-debuginfo~12.3.0~4.59.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-salt-minion", rpm:"open-vm-tools-salt-minion~12.3.0~4.59.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp", rpm:"open-vm-tools-sdmp~12.3.0~4.59.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp-debuginfo", rpm:"open-vm-tools-sdmp-debuginfo~12.3.0~4.59.1", rls:"SLES12.0SP5"))) {
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
