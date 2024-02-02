# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3654");
  script_cve_id("CVE-2021-41160", "CVE-2022-24883", "CVE-2022-39282", "CVE-2022-39283", "CVE-2022-39316", "CVE-2022-39318", "CVE-2022-39319", "CVE-2022-39347", "CVE-2022-41877");
  script_tag(name:"creation_date", value:"2023-11-20 04:23:43 +0000 (Mon, 20 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-06 13:51:41 +0000 (Fri, 06 May 2022)");

  script_name("Debian: Security Advisory (DLA-3654-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3654-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3654-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/freerdp2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freerdp2' package(s) announced via the DLA-3654-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Debian Bug : 1001062 1021659

Multiple vulnerabilties have been found in freelrdp2, a free implementation of the Remote Desktop Protocol (RDP). The vulnerabilties potentially allows authentication bypasses on configuration errors, buffer overreads, DoS vectors, buffer overflows or accessing files outside of a shared directory.

CVE-2021-41160

In affected versions a malicious server might trigger out of bound writes in a connected client. Connections using GDI or SurfaceCommands to send graphics updates to the client might send `0` width/height or out of bound rectangles to trigger out of bound writes. With `0` width or heigth the memory allocation will be `0` but the missing bounds checks allow writing to the pointer at this (not allocated) region.

CVE-2022-24883

Prior to version 2.7.0, server side authentication against a `SAM` file might be successful for invalid credentials if the server has configured an invalid `SAM` file path. FreeRDP based clients are not affected. RDP server implementations using FreeRDP to authenticate against a `SAM` file are affected. Version 2.7.0 contains a fix for this issue. As a workaround, use custom authentication via `HashCallback` and/or ensure the `SAM` database path configured is valid and the application has file handles left.

CVE-2022-39282

FreeRDP based clients on unix systems using `/parallel` command line switch might read uninitialized data and send it to the server the client is currently connected to. FreeRDP based server implementations are not affected.

CVE-2023-39283

All FreeRDP based clients when using the `/video` command line switch might read uninitialized data, decode it as audio/video and display the result. FreeRDP based server implementations are not affected.

CVE-2022-39316

In affected versions there is an out of bound read in ZGFX decoder component of FreeRDP. A malicious server can trick a FreeRDP based client to read out of bound data and try to decode it likely resulting in a crash.

CVE-2022-39318

Affected versions of FreeRDP are missing input validation in `urbdrc` channel. A malicious server can trick a FreeRDP based client to crash with division by zero.

CVE-2022-39319

Affected versions of FreeRDP are missing input length validation in the `urbdrc` channel. A malicious server can trick a FreeRDP based client to read out of bound data and send it back to the server.

CVE-2022-39347

Affected versions of FreeRDP are missing path canonicalization and base path check for `drive` channel. A malicious server can trick a FreeRDP based client to read files outside the shared directory.

CVE-2022-41877

Affected versions of FreeRDP are missing input length validation in `drive` channel. A malicious server can trick a FreeRDP based client to read out of bound data and send it back to the server.

For Debian 10 buster, these problems have been fixed in version 2.3.0+dfsg1-2+deb10u4.

We recommend that ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'freerdp2' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-dev", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-shadow-x11", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-wayland", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-x11", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client2-2", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-server2-2", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-shadow-subsystem2-2", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-shadow2-2", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuwac0-0", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuwac0-dev", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-tools2-2", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr2-2", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr2-dev", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"winpr-utils", ver:"2.3.0+dfsg1-2+deb10u4", rls:"DEB10"))) {
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
