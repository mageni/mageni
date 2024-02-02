# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5574");
  script_cve_id("CVE-2023-6185", "CVE-2023-6186");
  script_tag(name:"creation_date", value:"2023-12-12 04:23:36 +0000 (Tue, 12 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-14 14:41:30 +0000 (Thu, 14 Dec 2023)");

  script_name("Debian: Security Advisory (DSA-5574-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5574-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5574-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5574");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libreoffice");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libreoffice' package(s) announced via the DSA-5574-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Reginaldo Silva discovered two security vulnerabilities in LibreOffice, which could result in the execution of arbitrary scripts or Gstreamer plugins when opening a malformed file.

For the oldstable distribution (bullseye), these problems have been fixed in version 1:7.0.4-4+deb11u8.

For the stable distribution (bookworm), these problems have been fixed in version 4:7.4.7-1+deb12u1.

We recommend that you upgrade your libreoffice packages.

For the detailed security status of libreoffice please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Debian 11, Debian 12.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"fonts-opensymbol", ver:"2:102.11+LibO7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-lokdocview-0.1", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjuh-java", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjurt-java", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblibreoffice-java", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblibreofficekitgtk", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libofficebean-java", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-avmedia-backend-gstreamer", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base-core", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base-drivers", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base-nogui", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-calc", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-calc-nogui", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-common", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-core", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-core-nogui", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dev", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dev-common", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dev-doc", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dev-gui", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-draw", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-draw-nogui", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-evolution", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-gnome", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-gtk3", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ca", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-common", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-cs", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-da", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-de", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-dz", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-el", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-en-gb", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-en-us", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-es", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-et", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-eu", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-fi", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-fr", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-gl", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-hi", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-hu", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-id", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-it", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ja", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-km", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ko", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-nl", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-om", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-pl", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-pt", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-pt-br", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ru", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-sk", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-sl", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-sv", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-tr", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-vi", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-zh-cn", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-zh-tw", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-impress", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-impress-nogui", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-java-common", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-kde5", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-kf5", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-af", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-am", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ar", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-as", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ast", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-be", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-bg", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-bn", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-br", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-bs", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ca", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-cs", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-cy", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-da", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-de", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-dz", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-el", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-en-gb", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-en-za", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-eo", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-es", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-et", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-eu", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-fa", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-fi", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-fr", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ga", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gd", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gl", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gu", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gug", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-he", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-hi", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-hr", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-hu", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-id", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-in", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-is", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-it", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ja", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ka", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-kk", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-km", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-kmr", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-kn", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ko", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-lt", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-lv", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-mk", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ml", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-mn", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-mr", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nb", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ne", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nl", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nn", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nr", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nso", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-oc", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-om", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-or", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pa-in", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pl", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pt", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pt-br", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ro", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ru", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-rw", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-si", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sk", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sl", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sr", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ss", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-st", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sv", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-szl", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ta", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-te", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-tg", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-th", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-tn", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-tr", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ts", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ug", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-uk", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-uz", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ve", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-vi", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-xh", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-za", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-zh-cn", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-zh-tw", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-zu", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-librelogo", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-math", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-math-nogui", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-mysql-connector", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-nlpsolver", ver:"0.9+LibO7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-nogui", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-officebean", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-plasma", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-qt5", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-report-builder", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-report-builder-bin", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-report-builder-bin-nogui", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-script-provider-bsh", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-script-provider-js", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-script-provider-python", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-sdbc-firebird", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-sdbc-hsqldb", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-sdbc-mysql", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-sdbc-postgresql", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-smoketest-data", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-breeze", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-colibre", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-elementary", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-karasa-jaga", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-sifr", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-sukapura", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-subsequentcheckbase", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-wiki-publisher", ver:"1.2.0+LibO7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-writer", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-writer-nogui", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreofficekit-data", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreofficekit-dev", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libridl-java", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-cppu3", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-cppuhelpergcc3-3", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-purpenvhelpergcc3-3", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-sal3", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-salhelpergcc3-3", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libunoil-java", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libunoloader-java", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-access2base", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-uno", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uno-libs-private", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ure", ver:"1:7.0.4-4+deb11u8", rls:"DEB11"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"fonts-opensymbol", ver:"4:102.12+LibO7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-lokdocview-0.1", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblibreoffice-java", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblibreofficekitgtk", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libofficebean-java", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base-core", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base-drivers", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-base-nogui", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-calc", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-calc-nogui", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-common", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-core", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-core-nogui", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dev", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dev-common", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dev-doc", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-dev-gui", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-draw", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-draw-nogui", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-evolution", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-gnome", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-gtk3", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ca", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-common", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-cs", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-da", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-de", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-dz", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-el", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-en-gb", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-en-us", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-es", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-et", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-eu", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-fi", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-fr", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-gl", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-hi", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-hu", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-id", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-it", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ja", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-km", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ko", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-nl", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-om", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-pl", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-pt", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-pt-br", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-ru", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-sk", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-sl", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-sv", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-tr", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-vi", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-zh-cn", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-help-zh-tw", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-impress", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-impress-nogui", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-java-common", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-kf5", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-af", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-am", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ar", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-as", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ast", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-be", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-bg", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-bn", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-br", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-bs", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ca", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-cs", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-cy", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-da", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-de", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-dz", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-el", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-en-gb", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-en-za", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-eo", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-es", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-et", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-eu", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-fa", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-fi", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-fr", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ga", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gd", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gl", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gu", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-gug", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-he", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-hi", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-hr", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-hu", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-id", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-in", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-is", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-it", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ja", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ka", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-kk", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-km", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-kmr", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-kn", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ko", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-lt", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-lv", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-mk", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ml", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-mn", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-mr", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nb", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ne", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nl", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nn", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nr", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-nso", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-oc", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-om", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-or", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pa-in", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pl", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pt", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-pt-br", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ro", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ru", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-rw", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-si", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sk", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sl", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sr", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ss", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-st", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-sv", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-szl", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ta", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-te", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-tg", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-th", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-tn", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-tr", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ts", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ug", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-uk", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-uz", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-ve", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-vi", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-xh", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-za", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-zh-cn", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-zh-tw", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-l10n-zu", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-librelogo", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-math", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-math-nogui", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-nlpsolver", ver:"4:0.9+LibO7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-nogui", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-plasma", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-qt5", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-report-builder", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-report-builder-bin", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-report-builder-bin-nogui", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-script-provider-bsh", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-script-provider-js", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-script-provider-python", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-sdbc-firebird", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-sdbc-hsqldb", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-sdbc-mysql", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-sdbc-postgresql", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-smoketest-data", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-breeze", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-colibre", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-elementary", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-karasa-jaga", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-sifr", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-style-sukapura", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-subsequentcheckbase", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-wiki-publisher", ver:"4:1.2.0+LibO7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-writer", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-writer-nogui", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreofficekit-data", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreofficekit-dev", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-cppu3", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-cppuhelpergcc3-3", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-purpenvhelpergcc3-3", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-sal3", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuno-salhelpergcc3-3", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libunoloader-java", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-access2base", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-uno", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uno-libs-private", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ure", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ure-java", ver:"4:7.4.7-1+deb12u1", rls:"DEB12"))) {
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
