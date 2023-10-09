# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3596");
  script_cve_id("CVE-2022-27635", "CVE-2022-36351", "CVE-2022-38076", "CVE-2022-40964", "CVE-2022-46329");
  script_tag(name:"creation_date", value:"2023-10-02 04:20:39 +0000 (Mon, 02 Oct 2023)");
  script_version("2023-10-02T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-10-02 05:05:22 +0000 (Mon, 02 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-17 17:06:00 +0000 (Thu, 17 Aug 2023)");

  script_name("Debian: Security Advisory (DLA-3596)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3596");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3596");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00766.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/firmware-nonfree");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firmware-nonfree' package(s) announced via the DLA-3596 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Intel(r) released the INTEL-SA-00766 advisory about potential security vulnerabilities in some Intel(r) PROSet/Wireless WiFi and Killer(tm) WiFi products may allow escalation of privilege or denial of service. The full advisory is available at [1]

[1] [link moved to references]

This updated firmware-nonfree package includes the following firmware files: - Intel Bluetooth AX2xx series: ibt-0041-0041.sfi ibt-19-0-0.sfi ibt-19-0-1.sfi ibt-19-0-4.sfi ibt-19-16-4.sfi ibt-19-240-1.sfi ibt-19-240-4.sfi ibt-19-32-0.sfi ibt-19-32-1.sfi ibt-19-32-4.sfi ibt-20-0-3.sfi ibt-20-1-3.sfi ibt-20-1-4.sfi - Intel Wireless 22000 series iwlwifi-Qu-b0-hr-b0-77.ucode iwlwifi-Qu-b0-jf-b0-77.ucode iwlwifi-Qu-c0-hr-b0-77.ucode iwlwifi-Qu-c0-jf-b0-77.ucode iwlwifi-QuZ-a0-hr-b0-77.ucode iwlwifi-cc-a0-77.ucode

The updated firmware files might need updated kernel to work. It is encouraged to verify whether the kernel loaded the updated firmware file and take additional measures if needed.


CVE-2022-27635

Improper access control for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi software may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-36351

Improper input validation in some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi software may allow an unauthenticated user to potentially enable denial of service via adjacent access.

CVE-2022-38076

Improper input validation in some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi software may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-40964

Improper access control for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi software may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-46329

Protection mechanism failure for some Intel(R) PROSet/Wireless WiFi software may allow a privileged user to potentially enable escalation of privilege via local access.

For Debian 10 buster, these problems have been fixed in version 20190114+really20220913-0+deb10u2.

We recommend that you upgrade your firmware-nonfree packages.

For the detailed security status of firmware-nonfree please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'firmware-nonfree' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"firmware-adi", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-amd-graphics", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-atheros", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-bnx2", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-bnx2x", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-brcm80211", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-cavium", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-intel-sound", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-intelwimax", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-ipw2x00", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-ivtv", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-iwlwifi", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-libertas", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-linux", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-linux-nonfree", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-misc-nonfree", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-myricom", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-netronome", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-netxen", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-qcom-media", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-qlogic", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-ralink", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-realtek", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-samsung", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-siano", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-ti-connectivity", ver:"20190114+really20220913-0+deb10u2", rls:"DEB10"))) {
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
