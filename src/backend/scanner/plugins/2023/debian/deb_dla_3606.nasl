# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3606");
  script_cve_id("CVE-2020-11017", "CVE-2020-11018", "CVE-2020-11019", "CVE-2020-11038", "CVE-2020-11039", "CVE-2020-11040", "CVE-2020-11041", "CVE-2020-11042", "CVE-2020-11043", "CVE-2020-11044", "CVE-2020-11045", "CVE-2020-11046", "CVE-2020-11047", "CVE-2020-11048", "CVE-2020-11049", "CVE-2020-11058", "CVE-2020-11085", "CVE-2020-11086", "CVE-2020-11087", "CVE-2020-11088", "CVE-2020-11089", "CVE-2020-11095", "CVE-2020-11096", "CVE-2020-11097", "CVE-2020-11098", "CVE-2020-11099", "CVE-2020-13396", "CVE-2020-13397", "CVE-2020-13398", "CVE-2020-15103", "CVE-2020-4030", "CVE-2020-4031", "CVE-2020-4032", "CVE-2020-4033", "CVE-2023-39350", "CVE-2023-39351", "CVE-2023-39352", "CVE-2023-39353", "CVE-2023-39354", "CVE-2023-39355", "CVE-2023-39356", "CVE-2023-40181", "CVE-2023-40186", "CVE-2023-40188", "CVE-2023-40567", "CVE-2023-40569", "CVE-2023-40589");
  script_tag(name:"creation_date", value:"2023-10-09 04:24:08 +0000 (Mon, 09 Oct 2023)");
  script_version("2023-10-09T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-10-09 05:05:36 +0000 (Mon, 09 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-06 20:31:00 +0000 (Wed, 06 Sep 2023)");

  script_name("Debian: Security Advisory (DLA-3606)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3606");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3606");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/freerdp2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freerdp2' package(s) announced via the DLA-3606 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilties have been found in freelrdp2, a free implementation of the Remote Desktop Protocol (RDP). The vulnerabilties potentially allows buffer overreads, buffer overflows, interger overflows, use-after-free, DoS vectors.

CVE-2020-4030

In FreeRDP before version 2.1.2, there is an out of bounds read in TrioParse. Logging might bypass string length checks due to an integer overflow. This is fixed in version 2.1.2.

CVE-2020-4031

In FreeRDP before version 2.1.2, there is a use-after-free in gdi_SelectObject. All FreeRDP clients using compatibility mode with /relax-order-checks are affected. This is fixed in version 2.1.2.

CVE-2020-4032

In FreeRDP before version 2.1.2, there is an integer casting vulnerability in update_recv_secondary_order. All clients with +glyph-cache /relax-order-checks are affected. This is fixed in version 2.1.2.

CVE-2020-4033

In FreeRDP before version 2.1.2, there is an out of bounds read in RLEDECOMPRESS. All FreeRDP based clients with sessions with color depth < 32 are affected. This is fixed in version 2.1.2.

CVE-2020-11017

In FreeRDP less than or equal to 2.0.0, by providing manipulated input a malicious client can create a double free condition and crash the server. This is fixed in version 2.1.0.

CVE-2020-11018

In FreeRDP less than or equal to 2.0.0, a possible resource exhaustion vulnerability can be performed. Malicious clients could trigger out of bound reads causing memory allocation with random size. This has been fixed in 2.1.0.

CVE-2020-11019

In FreeRDP less than or equal to 2.0.0, when running with logger set to WLOG_TRACE, a possible crash of application could occur due to a read of an invalid array index. Data could be printed as string to local terminal. This has been fixed in 2.1.0.

CVE-2020-11038

In FreeRDP less than or equal to 2.0.0, an Integer Overflow to Buffer Overflow exists. When using /video redirection, a manipulated server can instruct the client to allocate a buffer with a smaller size than requested due to an integer overflow in size calculation. With later messages, the server can manipulate the client to write data out of bound to the previously allocated buffer. This has been patched in 2.1.0.

CVE-2020-11039

In FreeRDP less than or equal to 2.0.0, when using a manipulated server with USB redirection enabled (nearly) arbitrary memory can be read and written due to integer overflows in length checks. This has been patched in 2.1.0.

CVE-2020-11040

In FreeRDP less than or equal to 2.0.0, there is an out-of-bound data read from memory in clear_decompress_subcode_rlex, visualized on screen as color. This has been patched in 2.1.0.

CVE-2020-11041

In FreeRDP less than or equal to 2.0.0, an outside controlled array index is used unchecked for data used as configuration for sound backend (alsa, oss, pulse, ...). The most likely outcome is a crash of the client instance followed by no or ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-dev", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-shadow-x11", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-wayland", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freerdp2-x11", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client2-2", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-server2-2", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-shadow-subsystem2-2", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-shadow2-2", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuwac0-0", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libuwac0-dev", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-tools2-2", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr2-2", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr2-dev", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"winpr-utils", ver:"2.3.0+dfsg1-2+deb10u3", rls:"DEB10"))) {
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
