# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3585");
  script_cve_id("CVE-2020-18651", "CVE-2020-18652", "CVE-2021-36045", "CVE-2021-36046", "CVE-2021-36047", "CVE-2021-36048", "CVE-2021-36050", "CVE-2021-36051", "CVE-2021-36052", "CVE-2021-36053", "CVE-2021-36054", "CVE-2021-36055", "CVE-2021-36056", "CVE-2021-36057", "CVE-2021-36058", "CVE-2021-36064", "CVE-2021-39847", "CVE-2021-40716", "CVE-2021-40732", "CVE-2021-42528", "CVE-2021-42529", "CVE-2021-42530", "CVE-2021-42531", "CVE-2021-42532");
  script_tag(name:"creation_date", value:"2023-09-26 04:26:05 +0000 (Tue, 26 Sep 2023)");
  script_version("2023-09-26T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-09-26 05:05:30 +0000 (Tue, 26 Sep 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-11 00:36:00 +0000 (Wed, 11 May 2022)");

  script_name("Debian: Security Advisory (DLA-3585)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3585");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3585");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/exempi");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exempi' package(s) announced via the DLA-3585 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulneratibilities were found in exempi, an implementation of XMP (Extensible Metadata Platform).

CVE-2020-18651

A Buffer Overflow vulnerability was found in function ID3_Support::ID3v2Frame::getFrameValue allows remote attackers to cause a denial of service.

CVE-2020-18652

A Buffer Overflow vulnerability was found in WEBP_Support.cpp allows remote attackers to cause a denial of service.

CVE-2021-36045

An out-of-bounds read vulnerability was found that could lead to disclosure of arbitrary memory.

CVE-2021-36046

A memory corruption vulnerability was found, potentially resulting in arbitrary code execution in the context of the current use

CVE-2021-36047

An Improper Input Validation vulnerability was found, potentially resulting in arbitrary code execution in the context of the current use.

CVE-2021-36048

An Improper Input Validation was found, potentially resulting in arbitrary code execution in the context of the current user.

CVE-2021-36050

A buffer overflow vulnerability was found, potentially resulting in arbitrary code execution in the context of the current user.

CVE-2021-36051

A buffer overflow vulnerability was found, potentially resulting in arbitrary code execution in the context of the current user.

CVE-2021-36052

A memory corruption vulnerability was found, potentially resulting in arbitrary code execution in the context of the current user.

CVE-2021-36053

An out-of-bounds read vulnerability was found, that could lead to disclosure of arbitrary memory.

CVE-2021-36054

A buffer overflow vulnerability was found potentially resulting in local application denial of service.

CVE-2021-36055

A use-after-free vulnerability was found that could result in arbitrary code execution.

CVE-2021-36056

A buffer overflow vulnerability was found, potentially resulting in arbitrary code execution in the context of the current user.

CVE-2021-36057

A write-what-where condition vulnerability was found, caused during the application's memory allocation process. This may cause the memory management functions to become mismatched resulting in local application denial of service in the context of the current user.

CVE-2021-36058

An Integer Overflow vulnerability was found, potentially resulting in application-level denial of service in the context of the current user.

CVE-2021-36064

A Buffer Underflow vulnerability was found which could result in arbitrary code execution in the context of the current user

CVE-2021-39847

A stack-based buffer overflow vulnerability potentially resulting in arbitrary code execution in the context of the current user.

CVE-2021-40716

An out-of-bounds read vulnerability was found that could lead to disclosure of sensitive memory

CVE-2021-40732

A null pointer dereference vulnerability was found, that could result in leaking data from certain memory locations and causing a local denial of service

CVE-2021-42528

A ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'exempi' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"exempi", ver:"2.5.0-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexempi-dev", ver:"2.5.0-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexempi8", ver:"2.5.0-2+deb10u1", rls:"DEB10"))) {
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
