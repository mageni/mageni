# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0005.1");
  script_cve_id("CVE-2023-40475", "CVE-2023-44446");
  script_tag(name:"creation_date", value:"2024-01-03 04:20:17 +0000 (Wed, 03 Jan 2024)");
  script_version("2024-01-04T05:06:15+0000");
  script_tag(name:"last_modification", value:"2024-01-04 05:06:15 +0000 (Thu, 04 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0005-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0005-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240005-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-plugins-bad' package(s) announced via the SUSE-SU-2024:0005-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-bad fixes the following issues:

CVE-2023-44446: Fixed GStreamer MXF File Parsing Use-After-Free (bsc#1217213).
CVE-2023-40475: Fixed GStreamer MXF File Parsing Integer Overflow (bsc#1215792).");

  script_tag(name:"affected", value:"'gstreamer-plugins-bad' package(s) on SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Real Time 15-SP4, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3, SUSE Package Hub 15.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad", rpm:"gstreamer-plugins-bad~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint", rpm:"gstreamer-plugins-bad-chromaprint~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint-debuginfo", rpm:"gstreamer-plugins-bad-chromaprint-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-debuginfo", rpm:"gstreamer-plugins-bad-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-debugsource", rpm:"gstreamer-plugins-bad-debugsource~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-devel", rpm:"gstreamer-plugins-bad-devel~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-lang", rpm:"gstreamer-plugins-bad-lang~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0", rpm:"libgstadaptivedemux-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0-debuginfo", rpm:"libgstadaptivedemux-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0", rpm:"libgstbadaudio-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0-debuginfo", rpm:"libgstbadaudio-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0", rpm:"libgstbasecamerabinsrc-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0-debuginfo", rpm:"libgstbasecamerabinsrc-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0", rpm:"libgstcodecparsers-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0-debuginfo", rpm:"libgstcodecparsers-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecs-1_0-0", rpm:"libgstcodecs-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecs-1_0-0-debuginfo", rpm:"libgstcodecs-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0", rpm:"libgstinsertbin-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0-debuginfo", rpm:"libgstinsertbin-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0", rpm:"libgstisoff-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0-debuginfo", rpm:"libgstisoff-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0", rpm:"libgstmpegts-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0-debuginfo", rpm:"libgstmpegts-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0", rpm:"libgstphotography-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0-debuginfo", rpm:"libgstphotography-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplay-1_0-0", rpm:"libgstplay-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplay-1_0-0-debuginfo", rpm:"libgstplay-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0", rpm:"libgstplayer-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0-debuginfo", rpm:"libgstplayer-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0", rpm:"libgstsctp-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0-debuginfo", rpm:"libgstsctp-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0", rpm:"libgsturidownloader-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0-debuginfo", rpm:"libgsturidownloader-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstva-1_0-0", rpm:"libgstva-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstva-1_0-0-debuginfo", rpm:"libgstva-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvulkan-1_0-0", rpm:"libgstvulkan-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvulkan-1_0-0-debuginfo", rpm:"libgstvulkan-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0", rpm:"libgstwayland-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0-debuginfo", rpm:"libgstwayland-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0", rpm:"libgstwebrtc-1_0-0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0-debuginfo", rpm:"libgstwebrtc-1_0-0-debuginfo~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstBadAudio-1_0", rpm:"typelib-1_0-GstBadAudio-1_0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstCodecs-1_0", rpm:"typelib-1_0-GstCodecs-1_0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstInsertBin-1_0", rpm:"typelib-1_0-GstInsertBin-1_0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstMpegts-1_0", rpm:"typelib-1_0-GstMpegts-1_0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstPlay-1_0", rpm:"typelib-1_0-GstPlay-1_0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstPlayer-1_0", rpm:"typelib-1_0-GstPlayer-1_0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstWebRTC-1_0", rpm:"typelib-1_0-GstWebRTC-1_0~1.20.1~150400.3.15.1", rls:"SLES15.0SP4"))) {
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
