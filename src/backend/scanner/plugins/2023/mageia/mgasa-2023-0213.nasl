# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0213");
  script_cve_id("CVE-2021-20206", "CVE-2021-20291", "CVE-2021-34558", "CVE-2021-3602", "CVE-2021-4024", "CVE-2021-41190", "CVE-2022-1227", "CVE-2022-21698", "CVE-2022-27191", "CVE-2022-27649", "CVE-2022-27651", "CVE-2022-2989", "CVE-2022-2990");
  script_tag(name:"creation_date", value:"2023-07-10 04:12:52 +0000 (Mon, 10 Jul 2023)");
  script_version("2023-07-10T08:07:42+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:42 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-11 14:52:00 +0000 (Wed, 11 May 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0213)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0213");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0213.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28885");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SPYOHNG2Q7DCAQZMGYLMENLKALGDLG3X/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/25LCWXTFK5CEUYRWF74Y4C7VIMWDH2OI/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/R5D7XL7FL24TWFMGQ3K2S72EOUSLZMKL/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/F3ARUFZTP54XZ36JGEVCIBJZPX4LTF3G/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/GWKDCFQ4EVHMJJ6V2EAABHSRZK34HUUT/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IKOQ2O3CAYO75ZV2PUCTL6G72K7JVGCT/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/QKTJEKY2C35BIT22ZIPQZRQ4WY6ZW4W5/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/XOKBC52ABMXFW242S6YAQLBUX3QPEDOR/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/A4W4OXY44AKASYVR6NZPWKHHCVDI7LMX/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/HRFGZZIO26CZN3P2K72PZABZKT5J4IUT/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/OPCGIPJ4YWKRBYUO5NIO6H5RZROPWZVJ/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/ZNMB7O2UIXE34PGSCSOULGHPX5LIJBMM/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/XNDJJ36ISNZQL6I3K25POE5HZZJYUEIV/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/GDWE3ABI6VTR2BO4UV3HXEUYUN5CKUES/");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1969264");
  script_xref(name:"URL", value:"https://github.com/containers/buildah/security/advisories/GHSA-7638-r9r3-rmjj");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/ZAB6D3CGIKTOPITATFKEJEJZRRFUNAAF/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/WYEKQOCOMRYA54WFUPJNNBZD5CPNRGHX/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4ZGUZD4KLTFHCQDYKB64PUVEWIB3YTL2/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/LALQQUUGFHODEBITRRY26YKZFR2FQN5X/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/75MV35CPCW3Q5MAQR6OGEJEYVVEZ2MXI/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/CAYDF5STQQ2MWYFKJISEVKKCDRW6K3MP/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/WXJ2MVMAHOIGRH37ZSFYC4EVWLJFL2EQ/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/JYIUSR4YP52PWG7YE7AA3DZ5OSURNFJB/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/3TUZNDAH2B26VPBK342UC3BHZNLBUXGX/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IA7RFWWF2TAD6ABTSEOCANQQEGMSU4YP/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5BA2TLW7O5ZURGQUAQUH4HD5SQYNDDZ6/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WFIDXN6UAK2I4PPVFPBE4STNQH2FZQ4A/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/FY3N7H6VSDZM37B4SKM2PFFCUWU7QYWN/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2VWH6X6HOFPO6HTESF42HIJZEPXSWVIO/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/COAZMKGIFFK6JHHLFRHHTVMQ4HK5XI73/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/J5WPM42UR6XIBQNQPNQHM32X7S4LJTRX/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2IK53GWZ475OQ6ENABKMJMTOBZG6LXUR/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3XQI3JGSN3QUR2TTD5PKGO62TDA7VS3I/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BOSR3QWWI2B7POIUKKJJMCEE2T3PFI5B/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-October/012775.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PL4K6SMPK6ISI4ZPOM3PI6GAYO6XYPYB/");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2022:7822");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-January/013557.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NKDIDANN2OO6H6AMGCEODFI5ZES7PJYI/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/HX2XHVJTED7LYWP3LLJ3FTJMPQ4KYG44/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/I5RR5DUZHU2FFOE3EKYH6T74SA43EB4T/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4MA5XS5DAOJ5PKKNG5TUXKPQOFHT5VBC/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6170-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah, conmon, podman, skopeo' package(s) announced via the MGASA-2023-0213 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Information disclosure flaw was found in Buildah (CVE-2021-3602)
podman allows forwarding hosts ports to vm from within vm (CVE-2021-4024)
Allows use '../' separators in containernetworking/cni to reference
binaries such as 'reboot' in network configuration (CVE-2021-20206)
github.com/containers/storage ddos via crafted tar file (CVE-2021-20291)
buildah improper checking of X.509 certificate (CVE-2021-34558)
buildah improper Content-Type checking (CVE-2021-41190)
podman privilege escalation (CVE-2022-1227)
podman incorrect handling of the supplementary groups (CVE-2022-2989)
buildah incorrect handling of the supplementary groups (CVE-2022-2990)
skopeo/podman Denial of Service through unbounded cardinality, and
potential memory exhaustion (CVE-2022-21698)
buildah/podman AddHostKey denail of service (CVE-2022-27191)
podman inheritable file capabilities (CVE-2022-27649)
buildah inheritable file capabilities (CVE-2022-27651)");

  script_tag(name:"affected", value:"'buildah, conmon, podman, skopeo' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.30.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-tests", rpm:"buildah-tests~1.30.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon", rpm:"conmon~2.1.5~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containers-common", rpm:"containers-common~1.12.0~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~4.5.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-docker", rpm:"podman-docker~4.5.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-fish-completion", rpm:"podman-fish-completion~4.5.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-plugins", rpm:"podman-plugins~4.5.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote", rpm:"podman-remote~4.5.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-zsh-completion", rpm:"podman-zsh-completion~4.5.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo", rpm:"skopeo~1.12.0~2.mga8", rls:"MAGEIA8"))) {
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
