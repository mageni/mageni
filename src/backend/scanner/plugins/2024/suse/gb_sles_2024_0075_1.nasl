# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0075.1");
  script_cve_id("CVE-2023-0950", "CVE-2023-2255");
  script_tag(name:"creation_date", value:"2024-01-11 04:21:02 +0000 (Thu, 11 Jan 2024)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-07 17:42:02 +0000 (Wed, 07 Jun 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0075-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0075-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240075-1/");
  script_xref(name:"URL", value:"https://wiki.documentfoundation.org/ReleaseNotes/7.5");
  script_xref(name:"URL", value:"https://wiki.documentfoundation.org/ReleaseNotes/7.4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibreOffice' package(s) announced via the SUSE-SU-2024:0075-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for LibreOffice fixes the following issues:
libreoffice:

Version update from 7.3.6.2 to 7.5.4.1 (jsc#PED-3561, jsc#PED-3550, jsc#PED-1785):
For the highlights of changes of version 7.5 please consult the official release notes:
 [link moved to references] For the highlights of changes of version 7.4 please consult the official release notes:
 [link moved to references] Security issues fixed:
CVE-2023-0950: Fixed stack underflow in ScInterpreter (bsc#1209242)
CVE-2023-2255: Fixed vulnerability where remote documents could be loaded without prompt via IFrame (bsc#1211746)


Bug fixes:
Fix PPTX shadow effect for table offset (bsc#1204040)
Fix ability to set the default tab size for each text object (bsc#1198666)
Fix PPTX extra vertical space between different text formats (bsc#1200085)
Do not use binutils-gold as the package is unmaintainedd and will be removed in the future (bsc#1210687)


Updated bundled dependencies:
boost version update from 1_77_0 to 1_80_0 curl version update from 7.83.1 to 8.0.1 icu4c-data version update from 70_1 to 72_1 icu4c version update from 70_1 to 72_1 pdfium version update from 4699 to 5408 poppler version update from 21.11.0 to 22.12.0 poppler-data version update from 0.4.10 to 0.4.11 skia version from m97-a7230803d64ae9d44f4e128244480111a3ae967 to m103-b301ff025004c9cd82816c86c547588e6c24b466


New build dependencies:
fixmath-devel libwebp-devel zlib-devel dragonbox-devel at-spi2-core-devel libtiff-devel



dragonbox:

New package at version 1.1.3 (jsc#PED-1785)
New dependency for LibreOffice 7.4



fixmath:

New package at version 2022.07.20 (jsc#PED-1785)
New dependency for LibreOffice 7.4



libmwaw:

Version update from 0.3.20 to 0.3.21 (jsc#PED-1785):
Add debug code to read some private rsrc data Allow to read some MacWrite which does not have printer informations Add a parser for Scoop files Add a parser for ScriptWriter files Add a parser for ReadySetGo 1-4 files

xmlsec1:

Version update from 1.2.28 to 1.2.37 required by LibreOffice 7.5.2.2 (jsc#PED-3561, jsc#PED-3550):
Retired the XMLSec mailing list 'xmlsec@aleksey.com' and the XMLSec Online Signature Verifier.
Migration to OpenSSL 3.0 API Note that OpenSSL engines are disabled by default when XMLSec library is compiled
 against OpenSSL 3.0.
 To re-enable OpenSSL engines, use --enable-openssl3-engines configure flag
 (there will be a lot of deprecation warnings).
The OpenSSL before 1.1.0 and LibreSSL before 2.7.0 are now deprecated and will be removed in the future versions of
 XMLSec Library.
Refactored all the integer casts to ensure cast-safety. Fixed all warnings and enabled -Werror and -pedantic
 flags on CI builds.
Added configure flag to use size_t for xmlSecSize (currently disabled by default for backward compatibility).
Support for OpenSSL compiled with OPENSSL_NO_ERR.
Full support for LibreSSL 3.5.0 and ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'LibreOffice' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"atk-debugsource", rpm:"atk-debugsource~2.28.1~6.5.23", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atk-doc", rpm:"atk-doc~2.28.1~6.5.23", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atk-lang", rpm:"atk-lang~2.28.1~6.5.23", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatk-1_0-0", rpm:"libatk-1_0-0~2.28.1~6.5.23", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatk-1_0-0-32bit", rpm:"libatk-1_0-0-32bit~2.28.1~6.5.23", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatk-1_0-0-debuginfo", rpm:"libatk-1_0-0-debuginfo~2.28.1~6.5.23", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libatk-1_0-0-debuginfo-32bit", rpm:"libatk-1_0-0-debuginfo-32bit~2.28.1~6.5.23", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-1", rpm:"libxmlsec1-1~1.2.37~8.6.21", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-1-debuginfo", rpm:"libxmlsec1-1-debuginfo~1.2.37~8.6.21", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-gcrypt1", rpm:"libxmlsec1-gcrypt1~1.2.37~8.6.21", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-gcrypt1-debuginfo", rpm:"libxmlsec1-gcrypt1-debuginfo~1.2.37~8.6.21", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-gnutls1", rpm:"libxmlsec1-gnutls1~1.2.37~8.6.21", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-gnutls1-debuginfo", rpm:"libxmlsec1-gnutls1-debuginfo~1.2.37~8.6.21", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-nss1", rpm:"libxmlsec1-nss1~1.2.37~8.6.21", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-nss1-debuginfo", rpm:"libxmlsec1-nss1-debuginfo~1.2.37~8.6.21", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-openssl1", rpm:"libxmlsec1-openssl1~1.2.37~8.6.21", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-openssl1-debuginfo", rpm:"libxmlsec1-openssl1-debuginfo~1.2.37~8.6.21", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Atk-1_0", rpm:"typelib-1_0-Atk-1_0~2.28.1~6.5.23", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlsec1", rpm:"xmlsec1~1.2.37~8.6.21", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlsec1-debuginfo", rpm:"xmlsec1-debuginfo~1.2.37~8.6.21", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlsec1-debugsource", rpm:"xmlsec1-debugsource~1.2.37~8.6.21", rls:"SLES12.0SP5"))) {
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
