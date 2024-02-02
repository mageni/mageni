# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0007");
  script_cve_id("CVE-2023-47359", "CVE-2023-47360");
  script_tag(name:"creation_date", value:"2024-01-15 04:12:30 +0000 (Mon, 15 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-13 19:31:30 +0000 (Mon, 13 Nov 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0007)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0007");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0007.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32487");
  script_xref(name:"URL", value:"https://lwn.net/Articles/950049/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc' package(s) announced via the MGASA-2024-0007 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:
Videolan VLC prior to version 3.0.20 contains an incorrect offset read
that leads to a Heap-Based Buffer Overflow in function GetPacket() and
results in a memory corruption (CVE-2023-47359).
Videolan VLC prior to version 3.0.20 contains an Integer underflow that
leads to an incorrect packet length (CVE-2023-47360).");

  script_tag(name:"affected", value:"'vlc' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc-devel", rpm:"lib64vlc-devel~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc-devel", rpm:"lib64vlc-devel~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc5", rpm:"lib64vlc5~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlc5", rpm:"lib64vlc5~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlccore9", rpm:"lib64vlccore9~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vlccore9", rpm:"lib64vlccore9~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc-devel", rpm:"libvlc-devel~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc-devel", rpm:"libvlc-devel~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore9", rpm:"libvlccore9~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore9", rpm:"libvlccore9~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"svlc", rpm:"svlc~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"svlc", rpm:"svlc~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc", rpm:"vlc~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc", rpm:"vlc~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-aa", rpm:"vlc-plugin-aa~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-aa", rpm:"vlc-plugin-aa~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-chromaprint", rpm:"vlc-plugin-chromaprint~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-chromaprint", rpm:"vlc-plugin-chromaprint~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-common", rpm:"vlc-plugin-common~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-common", rpm:"vlc-plugin-common~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-dv", rpm:"vlc-plugin-dv~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-dv", rpm:"vlc-plugin-dv~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-fdkaac", rpm:"vlc-plugin-fdkaac~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-flac", rpm:"vlc-plugin-flac~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-flac", rpm:"vlc-plugin-flac~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-fluidsynth", rpm:"vlc-plugin-fluidsynth~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-fluidsynth", rpm:"vlc-plugin-fluidsynth~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gme", rpm:"vlc-plugin-gme~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gme", rpm:"vlc-plugin-gme~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gnutls", rpm:"vlc-plugin-gnutls~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-gnutls", rpm:"vlc-plugin-gnutls~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-jack", rpm:"vlc-plugin-jack~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-jack", rpm:"vlc-plugin-jack~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-kate", rpm:"vlc-plugin-kate~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-kate", rpm:"vlc-plugin-kate~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libass", rpm:"vlc-plugin-libass~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libass", rpm:"vlc-plugin-libass~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libnotify", rpm:"vlc-plugin-libnotify~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-libnotify", rpm:"vlc-plugin-libnotify~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lirc", rpm:"vlc-plugin-lirc~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lirc", rpm:"vlc-plugin-lirc~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lua", rpm:"vlc-plugin-lua~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-lua", rpm:"vlc-plugin-lua~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mod", rpm:"vlc-plugin-mod~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mod", rpm:"vlc-plugin-mod~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mpc", rpm:"vlc-plugin-mpc~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-mpc", rpm:"vlc-plugin-mpc~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-ncurses", rpm:"vlc-plugin-ncurses~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-ncurses", rpm:"vlc-plugin-ncurses~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-opengl", rpm:"vlc-plugin-opengl~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-opengl", rpm:"vlc-plugin-opengl~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-projectm", rpm:"vlc-plugin-projectm~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-projectm", rpm:"vlc-plugin-projectm~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-pulse", rpm:"vlc-plugin-pulse~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-pulse", rpm:"vlc-plugin-pulse~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-rist", rpm:"vlc-plugin-rist~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-rist", rpm:"vlc-plugin-rist~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-samba", rpm:"vlc-plugin-samba~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-samba", rpm:"vlc-plugin-samba~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-schroedinger", rpm:"vlc-plugin-schroedinger~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-schroedinger", rpm:"vlc-plugin-schroedinger~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sdl", rpm:"vlc-plugin-sdl~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sdl", rpm:"vlc-plugin-sdl~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-shout", rpm:"vlc-plugin-shout~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-shout", rpm:"vlc-plugin-shout~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sid", rpm:"vlc-plugin-sid~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sid", rpm:"vlc-plugin-sid~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sndio", rpm:"vlc-plugin-sndio~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-sndio", rpm:"vlc-plugin-sndio~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-speex", rpm:"vlc-plugin-speex~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-speex", rpm:"vlc-plugin-speex~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-theora", rpm:"vlc-plugin-theora~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-theora", rpm:"vlc-plugin-theora~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-twolame", rpm:"vlc-plugin-twolame~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-twolame", rpm:"vlc-plugin-twolame~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-upnp", rpm:"vlc-plugin-upnp~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-upnp", rpm:"vlc-plugin-upnp~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-vdpau", rpm:"vlc-plugin-vdpau~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-vdpau", rpm:"vlc-plugin-vdpau~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-zvbi", rpm:"vlc-plugin-zvbi~3.0.20~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-plugin-zvbi", rpm:"vlc-plugin-zvbi~3.0.20~1.mga9.tainted", rls:"MAGEIA9"))) {
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
