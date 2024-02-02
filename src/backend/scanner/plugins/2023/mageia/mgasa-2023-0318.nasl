# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0318");
  script_cve_id("CVE-2023-39350", "CVE-2023-39351", "CVE-2023-39353", "CVE-2023-39354", "CVE-2023-40181", "CVE-2023-40186", "CVE-2023-40188", "CVE-2023-40567", "CVE-2023-40569", "CVE-2023-40589");
  script_tag(name:"creation_date", value:"2023-11-16 04:12:21 +0000 (Thu, 16 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-06 20:31:55 +0000 (Wed, 06 Sep 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0318)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0318");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0318.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32360");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6401-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the MGASA-2023-0318 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This issue affects Clients only: Integer underflow leading to DOS (e.g.
abort due to `WINPR_ASSERT` with default compilation flags). When an
insufficient blockLen is provided, and proper length validation is not
performed, an Integer Underflow occurs, leading to a Denial of Service
(DOS) vulnerability. (CVE-2023-39350)


Affected versions of FreeRDP are subject to a Null Pointer Dereference
leading a crash in the RemoteFX (rfx) handling. Inside the
`rfx_process_message_tileset` function, the program allocates tiles
using `rfx_allocate_tiles` for the number of numTiles. If the
initialization process of tiles is not completed for various reasons,
tiles will have a NULL pointer. Which may be accessed in further
processing and would cause a program crash. (CVE-2023-39351)

Affected versions are subject to a missing offset validation leading to
Out Of Bound Read. In the `libfreerdp/codec/rfx.c` file there is no offset validation in `tile->quantIdxY`, `tile->quantIdxCb`, and
`tile->quantIdxCr`. As a result crafted input can lead to an out of
bounds read access which in turn will cause a crash. (CVE-2023-39353)

Affected versions are subject to an Out-Of-Bounds Read in the
`nsc_rle_decompress_data` function. The Out-Of-Bounds Read occurs
because it processes `context->Planes` without checking if it contains
data of sufficient length. Should an attacker be able to leverage this
vulnerability they may be able to cause a crash. (CVE-2023-39354)

Affected versions are subject to an Integer-Underflow leading to
Out-Of-Bound Read in the `zgfx_decompress_segment` function. In the
context of `CopyMemory`, it's possible to read data beyond the
transmitted packet range and likely cause a crash. (CVE-2023-40181)

Affected versions are subject to an IntegerOverflow leading to
Out-Of-Bound Write Vulnerability in the `gdi_CreateSurface` function.
This issue affects FreeRDP based clients only. FreeRDP proxies are not
affected as image decoding is not done by a proxy. (CVE-2023-40186)

Affected versions are subject to an Out-Of-Bounds Read in the
`general_LumaToYUV444` function. This Out-Of-Bounds Read occurs because
processing is done on the `in` variable without checking if it contains
data of sufficient length. Insufficient data for the `in` variable may
cause errors or crashes. (CVE-2023-40188)

Affected versions are subject to an Out-Of-Bounds Write in the
`clear_decompress_bands_data` function in which there is no offset
validation. Abuse of this vulnerability may lead to an out of bounds
write. (CVE-2023-40567)

Affected versions are subject to an Out-Of-Bounds Write in the
`progressive_decompress` function. This issue is likely down to
incorrect calculations of the `nXSrc` and `nYSrc` variables.
(CVE-2023-40569)

In affected versions there is a Global-Buffer-Overflow in the
ncrush_decompress function. Feeding crafted input into this function can
trigger the overflow which has only been shown to cause a crash.
(CVE-2023-40589)");

  script_tag(name:"affected", value:"'freerdp' package(s) on Mageia 8, Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.9.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp-devel", rpm:"lib64freerdp-devel~2.9.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp2", rpm:"lib64freerdp2~2.9.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp-devel", rpm:"libfreerdp-devel~2.9.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.9.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.10.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp-devel", rpm:"lib64freerdp-devel~2.10.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp2", rpm:"lib64freerdp2~2.10.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp-devel", rpm:"libfreerdp-devel~2.10.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.10.0~2.1.mga9", rls:"MAGEIA9"))) {
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
