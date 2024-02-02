# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0354");
  script_cve_id("CVE-2022-1920", "CVE-2022-1922", "CVE-2022-1923", "CVE-2022-1924", "CVE-2022-1925", "CVE-2022-2122", "CVE-2023-37327", "CVE-2023-37328", "CVE-2023-37329", "CVE-2023-38103", "CVE-2023-38104", "CVE-2023-40474", "CVE-2023-40475", "CVE-2023-40476", "CVE-2023-44429", "CVE-2023-44446");
  script_tag(name:"creation_date", value:"2023-12-25 04:12:15 +0000 (Mon, 25 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-26 22:30:03 +0000 (Tue, 26 Jul 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0354)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0354");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0354.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32071");
  script_xref(name:"URL", value:"https://gstreamer.freedesktop.org/security/sa-2023-0011.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer1.0, gstreamer1.0-devtools, gstreamer1.0-editing-services, gstreamer1.0-libav, gstreamer1.0-moodbar, gstreamer1.0-omx, gstreamer1.0-plugins-bad, gstreamer1.0-plugins-base, gstreamer1.0-plugins-good, gstreamer1.0-plugins-ugly, gstreamer1.0-python, gstreamer1.0-rtsp-server, gstreamer1.0-vaapi' package(s) announced via the MGASA-2023-0354 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated gstreamer packages fix many security issues (see the references
below).
Apart from the listed CVEs, ZDI-CAN-22300 is also fixed.");

  script_tag(name:"affected", value:"'gstreamer1.0, gstreamer1.0-devtools, gstreamer1.0-editing-services, gstreamer1.0-libav, gstreamer1.0-moodbar, gstreamer1.0-omx, gstreamer1.0-plugins-bad, gstreamer1.0-plugins-base, gstreamer1.0-plugins-good, gstreamer1.0-plugins-ugly, gstreamer1.0-python, gstreamer1.0-rtsp-server, gstreamer1.0-vaapi' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0", rpm:"gstreamer1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-a52dec", rpm:"gstreamer1.0-a52dec~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-a52dec", rpm:"gstreamer1.0-a52dec~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-aalib", rpm:"gstreamer1.0-aalib~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-amrnb", rpm:"gstreamer1.0-amrnb~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-amrwbdec", rpm:"gstreamer1.0-amrwbdec~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-caca", rpm:"gstreamer1.0-caca~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdio", rpm:"gstreamer1.0-cdio~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdio", rpm:"gstreamer1.0-cdio~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdparanoia", rpm:"gstreamer1.0-cdparanoia~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-curl", rpm:"gstreamer1.0-curl~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-curl", rpm:"gstreamer1.0-curl~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dash", rpm:"gstreamer1.0-dash~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dash", rpm:"gstreamer1.0-dash~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-de265", rpm:"gstreamer1.0-de265~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-devtools", rpm:"gstreamer1.0-devtools~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dv", rpm:"gstreamer1.0-dv~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-editing-services", rpm:"gstreamer1.0-editing-services~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-editing-services-python", rpm:"gstreamer1.0-editing-services-python~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-faad", rpm:"gstreamer1.0-faad~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-fdkaac", rpm:"gstreamer1.0-fdkaac~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-flac", rpm:"gstreamer1.0-flac~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-fluidsynth", rpm:"gstreamer1.0-fluidsynth~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-fluidsynth", rpm:"gstreamer1.0-fluidsynth~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gme", rpm:"gstreamer1.0-gme~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gme", rpm:"gstreamer1.0-gme~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gsm", rpm:"gstreamer1.0-gsm~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-gsm", rpm:"gstreamer1.0-gsm~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-jack", rpm:"gstreamer1.0-jack~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ladspa", rpm:"gstreamer1.0-ladspa~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-ladspa", rpm:"gstreamer1.0-ladspa~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-lame", rpm:"gstreamer1.0-lame~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libass", rpm:"gstreamer1.0-libass~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libass", rpm:"gstreamer1.0-libass~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libav", rpm:"gstreamer1.0-libav~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libvisual", rpm:"gstreamer1.0-libvisual~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-moodbar", rpm:"gstreamer1.0-moodbar~1.2.1~5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg", rpm:"gstreamer1.0-mpeg~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg", rpm:"gstreamer1.0-mpeg~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg2enc", rpm:"gstreamer1.0-mpeg2enc~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-mpeg2enc", rpm:"gstreamer1.0-mpeg2enc~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-neon", rpm:"gstreamer1.0-neon~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-neon", rpm:"gstreamer1.0-neon~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-nle", rpm:"gstreamer1.0-nle~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-omx", rpm:"gstreamer1.0-omx~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-bad", rpm:"gstreamer1.0-plugins-bad~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-bad", rpm:"gstreamer1.0-plugins-bad~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-base", rpm:"gstreamer1.0-plugins-base~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-good", rpm:"gstreamer1.0-plugins-good~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-ugly", rpm:"gstreamer1.0-plugins-ugly~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-ugly", rpm:"gstreamer1.0-plugins-ugly~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-pulse", rpm:"gstreamer1.0-pulse~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-python", rpm:"gstreamer1.0-python~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-raw1394", rpm:"gstreamer1.0-raw1394~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-rtmp", rpm:"gstreamer1.0-rtmp~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-rtmp", rpm:"gstreamer1.0-rtmp~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-rtsp-server", rpm:"gstreamer1.0-rtsp-server~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-rtspclientsink", rpm:"gstreamer1.0-rtspclientsink~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sbc", rpm:"gstreamer1.0-sbc~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sbc", rpm:"gstreamer1.0-sbc~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sid", rpm:"gstreamer1.0-sid~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-sid", rpm:"gstreamer1.0-sid~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-smoothstreaming", rpm:"gstreamer1.0-smoothstreaming~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-smoothstreaming", rpm:"gstreamer1.0-smoothstreaming~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soundtouch", rpm:"gstreamer1.0-soundtouch~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soundtouch", rpm:"gstreamer1.0-soundtouch~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soup", rpm:"gstreamer1.0-soup~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-speex", rpm:"gstreamer1.0-speex~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-srtp", rpm:"gstreamer1.0-srtp~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-srtp", rpm:"gstreamer1.0-srtp~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-tools", rpm:"gstreamer1.0-tools~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-transcoder", rpm:"gstreamer1.0-transcoder~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-transcoder", rpm:"gstreamer1.0-transcoder~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-twolame", rpm:"gstreamer1.0-twolame~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-vaapi", rpm:"gstreamer1.0-vaapi~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-validate-scenarios", rpm:"gstreamer1.0-validate-scenarios~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-vp8", rpm:"gstreamer1.0-vp8~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wavpack", rpm:"gstreamer1.0-wavpack~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wildmidi", rpm:"gstreamer1.0-wildmidi~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wildmidi", rpm:"gstreamer1.0-wildmidi~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-x264", rpm:"gstreamer1.0-x264~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-x265", rpm:"gstreamer1.0-x265~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cudagst1.0", rpm:"lib64cudagst1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cudagst1.0", rpm:"lib64cudagst1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ges-gir1.0", rpm:"lib64ges-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ges1.0-devel", rpm:"lib64ges1.0-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ges1.0_0", rpm:"lib64ges1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64girgstmpegts-gir1.0", rpm:"lib64girgstmpegts-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64girgstmpegts-gir1.0", rpm:"lib64girgstmpegts-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64girinsertbin-git1.0", rpm:"lib64girinsertbin-git1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64girinsertbin-git1.0", rpm:"lib64girinsertbin-git1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gst-gir1.0", rpm:"lib64gst-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadaudio-gir1.0", rpm:"lib64gstbadaudio-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadaudio-gir1.0", rpm:"lib64gstbadaudio-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadaudio1.0_0", rpm:"lib64gstbadaudio1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbadaudio1.0_0", rpm:"lib64gstbadaudio1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasecamerabinsrc1.0_0", rpm:"lib64gstbasecamerabinsrc1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstbasecamerabinsrc1.0_0", rpm:"lib64gstbasecamerabinsrc1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecparsers1.0_0", rpm:"lib64gstcodecparsers1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecparsers1.0_0", rpm:"lib64gstcodecparsers1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecs-gir1.0", rpm:"lib64gstcodecs-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecs-gir1.0", rpm:"lib64gstcodecs-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecs1.0_0", rpm:"lib64gstcodecs1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcodecs1.0_0", rpm:"lib64gstcodecs1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcuda-gir1.0", rpm:"lib64gstcuda-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcuda-gir1.0", rpm:"lib64gstcuda-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcuda1.0_0", rpm:"lib64gstcuda1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstcuda1.0_0", rpm:"lib64gstcuda1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstgl-gir1.0", rpm:"lib64gstgl-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstgl1.0_0", rpm:"lib64gstgl1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstinsertbin1.0_0", rpm:"lib64gstinsertbin1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstinsertbin1.0_0", rpm:"lib64gstinsertbin1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstisoff1.0_0", rpm:"lib64gstisoff1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstisoff1.0_0", rpm:"lib64gstisoff1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstmpegts1.0_0", rpm:"lib64gstmpegts1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstmpegts1.0_0", rpm:"lib64gstmpegts1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography1.0_0", rpm:"lib64gstphotography1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstphotography1.0_0", rpm:"lib64gstphotography1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplay-gir1.0", rpm:"lib64gstplay-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplay-gir1.0", rpm:"lib64gstplay-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplay1.0_0", rpm:"lib64gstplay1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplay1.0_0", rpm:"lib64gstplay1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplayer-gir1.0", rpm:"lib64gstplayer-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplayer-gir1.0", rpm:"lib64gstplayer-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplayer1.0_0", rpm:"lib64gstplayer1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstplayer1.0_0", rpm:"lib64gstplayer1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-bad1.0-devel", rpm:"lib64gstreamer-plugins-bad1.0-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-bad1.0-devel", rpm:"lib64gstreamer-plugins-bad1.0-devel~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base-gir1.0", rpm:"lib64gstreamer-plugins-base-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base1.0-devel", rpm:"lib64gstreamer-plugins-base1.0-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base1.0_0", rpm:"lib64gstreamer-plugins-base1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer1.0-devel", rpm:"lib64gstreamer1.0-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer1.0_0", rpm:"lib64gstreamer1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstrtspserver-devel", rpm:"lib64gstrtspserver-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstrtspserver-gir1.0", rpm:"lib64gstrtspserver-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstrtspserver1.0_0", rpm:"lib64gstrtspserver1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstsctp1.0_0", rpm:"lib64gstsctp1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstsctp1.0_0", rpm:"lib64gstsctp1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsttranscoder-devel", rpm:"lib64gsttranscoder-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsttranscoder-devel", rpm:"lib64gsttranscoder-devel~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsttranscoder-gir1.0", rpm:"lib64gsttranscoder-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsttranscoder-gir1.0", rpm:"lib64gsttranscoder-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsttranscoder1.0_0", rpm:"lib64gsttranscoder1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsttranscoder1.0_0", rpm:"lib64gsttranscoder1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsturidownloader1.0_0", rpm:"lib64gsturidownloader1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsturidownloader1.0_0", rpm:"lib64gsturidownloader1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstva-gir1.0", rpm:"lib64gstva-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstva-gir1.0", rpm:"lib64gstva-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstva1.0_0", rpm:"lib64gstva1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstva1.0_0", rpm:"lib64gstva1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstvalidate-gir1.0", rpm:"lib64gstvalidate-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstvalidate1.0-devel", rpm:"lib64gstvalidate1.0-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstvalidate1.0_0", rpm:"lib64gstvalidate1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwayland1.0_0", rpm:"lib64gstwayland1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwayland1.0_0", rpm:"lib64gstwayland1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtc-gir1.0", rpm:"lib64gstwebrtc-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtc-gir1.0", rpm:"lib64gstwebrtc-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtc1.0_0", rpm:"lib64gstwebrtc1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtc1.0_0", rpm:"lib64gstwebrtc1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtcnice1.0_0", rpm:"lib64gstwebrtcnice1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstwebrtcnice1.0_0", rpm:"lib64gstwebrtcnice1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcudagst1.0", rpm:"libcudagst1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcudagst1.0", rpm:"libcudagst1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libges-gir1.0", rpm:"libges-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libges1.0-devel", rpm:"libges1.0-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libges1.0_0", rpm:"libges1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgirgstmpegts-gir1.0", rpm:"libgirgstmpegts-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgirgstmpegts-gir1.0", rpm:"libgirgstmpegts-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgirinsertbin-git1.0", rpm:"libgirinsertbin-git1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgirinsertbin-git1.0", rpm:"libgirinsertbin-git1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgst-gir1.0", rpm:"libgst-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-gir1.0", rpm:"libgstbadaudio-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-gir1.0", rpm:"libgstbadaudio-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio1.0_0", rpm:"libgstbadaudio1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio1.0_0", rpm:"libgstbadaudio1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc1.0_0", rpm:"libgstbasecamerabinsrc1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc1.0_0", rpm:"libgstbasecamerabinsrc1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers1.0_0", rpm:"libgstcodecparsers1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers1.0_0", rpm:"libgstcodecparsers1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecs-gir1.0", rpm:"libgstcodecs-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecs-gir1.0", rpm:"libgstcodecs-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecs1.0_0", rpm:"libgstcodecs1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecs1.0_0", rpm:"libgstcodecs1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcuda-gir1.0", rpm:"libgstcuda-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcuda-gir1.0", rpm:"libgstcuda-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcuda1.0_0", rpm:"libgstcuda1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcuda1.0_0", rpm:"libgstcuda1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-gir1.0", rpm:"libgstgl-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl1.0_0", rpm:"libgstgl1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin1.0_0", rpm:"libgstinsertbin1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin1.0_0", rpm:"libgstinsertbin1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff1.0_0", rpm:"libgstisoff1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff1.0_0", rpm:"libgstisoff1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts1.0_0", rpm:"libgstmpegts1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts1.0_0", rpm:"libgstmpegts1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography1.0_0", rpm:"libgstphotography1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography1.0_0", rpm:"libgstphotography1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplay-gir1.0", rpm:"libgstplay-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplay-gir1.0", rpm:"libgstplay-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplay1.0_0", rpm:"libgstplay1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplay1.0_0", rpm:"libgstplay1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-gir1.0", rpm:"libgstplayer-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-gir1.0", rpm:"libgstplayer-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer1.0_0", rpm:"libgstplayer1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer1.0_0", rpm:"libgstplayer1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-bad1.0-devel", rpm:"libgstreamer-plugins-bad1.0-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-bad1.0-devel", rpm:"libgstreamer-plugins-bad1.0-devel~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base-gir1.0", rpm:"libgstreamer-plugins-base-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base1.0-devel", rpm:"libgstreamer-plugins-base1.0-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base1.0_0", rpm:"libgstreamer-plugins-base1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer1.0-devel", rpm:"libgstreamer1.0-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer1.0_0", rpm:"libgstreamer1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtspserver-devel", rpm:"libgstrtspserver-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtspserver-gir1.0", rpm:"libgstrtspserver-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtspserver1.0_0", rpm:"libgstrtspserver1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp1.0_0", rpm:"libgstsctp1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp1.0_0", rpm:"libgstsctp1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttranscoder-devel", rpm:"libgsttranscoder-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttranscoder-devel", rpm:"libgsttranscoder-devel~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttranscoder-gir1.0", rpm:"libgsttranscoder-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttranscoder-gir1.0", rpm:"libgsttranscoder-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttranscoder1.0_0", rpm:"libgsttranscoder1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttranscoder1.0_0", rpm:"libgsttranscoder1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader1.0_0", rpm:"libgsturidownloader1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader1.0_0", rpm:"libgsturidownloader1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstva-gir1.0", rpm:"libgstva-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstva-gir1.0", rpm:"libgstva-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstva1.0_0", rpm:"libgstva1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstva1.0_0", rpm:"libgstva1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvalidate-gir1.0", rpm:"libgstvalidate-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvalidate1.0-devel", rpm:"libgstvalidate1.0-devel~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvalidate1.0_0", rpm:"libgstvalidate1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland1.0_0", rpm:"libgstwayland1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland1.0_0", rpm:"libgstwayland1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-gir1.0", rpm:"libgstwebrtc-gir1.0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-gir1.0", rpm:"libgstwebrtc-gir1.0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc1.0_0", rpm:"libgstwebrtc1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc1.0_0", rpm:"libgstwebrtc1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtcnice1.0_0", rpm:"libgstwebrtcnice1.0_0~1.22.8~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtcnice1.0_0", rpm:"libgstwebrtcnice1.0_0~1.22.8~1.mga9.tainted", rls:"MAGEIA9"))) {
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
