# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4368.1");
  script_cve_id("CVE-2023-40474");
  script_tag(name:"creation_date", value:"2023-11-07 04:30:44 +0000 (Tue, 07 Nov 2023)");
  script_version("2023-11-07T05:06:14+0000");
  script_tag(name:"last_modification", value:"2023-11-07 05:06:14 +0000 (Tue, 07 Nov 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4368-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4368-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234368-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-plugins-bad' package(s) announced via the SUSE-SU-2023:4368-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-bad fixes the following issues:

CVE-2023-40474: Fixed a remote code execution issue due to improper parsing of H265 encoded video files (bsc#1215793).");

  script_tag(name:"affected", value:"'gstreamer-plugins-bad' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad", rpm:"gstreamer-plugins-bad~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-debuginfo", rpm:"gstreamer-plugins-bad-debuginfo~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-debugsource", rpm:"gstreamer-plugins-bad-debugsource~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-lang", rpm:"gstreamer-plugins-bad-lang~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0", rpm:"libgstadaptivedemux-1_0-0~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0-debuginfo", rpm:"libgstadaptivedemux-1_0-0-debuginfo~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0", rpm:"libgstbadaudio-1_0-0~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0-debuginfo", rpm:"libgstbadaudio-1_0-0-debuginfo~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadbase-1_0-0", rpm:"libgstbadbase-1_0-0~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadbase-1_0-0-debuginfo", rpm:"libgstbadbase-1_0-0-debuginfo~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadvideo-1_0-0", rpm:"libgstbadvideo-1_0-0~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadvideo-1_0-0-debuginfo", rpm:"libgstbadvideo-1_0-0-debuginfo~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0", rpm:"libgstbasecamerabinsrc-1_0-0~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0-debuginfo", rpm:"libgstbasecamerabinsrc-1_0-0-debuginfo~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0", rpm:"libgstcodecparsers-1_0-0~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0-debuginfo", rpm:"libgstcodecparsers-1_0-0-debuginfo~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0", rpm:"libgstgl-1_0-0~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0-debuginfo", rpm:"libgstgl-1_0-0-debuginfo~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0", rpm:"libgstmpegts-1_0-0~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0-debuginfo", rpm:"libgstmpegts-1_0-0-debuginfo~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0", rpm:"libgstphotography-1_0-0~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0-debuginfo", rpm:"libgstphotography-1_0-0-debuginfo~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0", rpm:"libgsturidownloader-1_0-0~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0-debuginfo", rpm:"libgsturidownloader-1_0-0-debuginfo~1.8.3~18.6.1", rls:"SLES12.0SP5"))) {
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
