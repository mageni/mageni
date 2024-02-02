# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3668");
  script_cve_id("CVE-2023-40660", "CVE-2023-40661");
  script_tag(name:"creation_date", value:"2023-11-27 04:28:29 +0000 (Mon, 27 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 17:12:25 +0000 (Tue, 14 Nov 2023)");

  script_name("Debian: Security Advisory (DLA-3668-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3668-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3668-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/opensc");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'opensc' package(s) announced via the DLA-3668-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerabilities were found in opensc, a set of libraries and utilities to access smart cards, which could lead to application crash or authentication bypass.

CVE-2023-40660

When the token/card was plugged into the computer and authenticated from one process, it could be used to provide cryptographic operations from different process when the empty, zero-length PIN and the token can track the login status using some of its internals. This is dangerous for OS logon/screen unlock and small tokens that are plugged permanently to the computer.

The bypass was removed and explicit logout implemented for most of the card drivers to prevent leaving unattended logged-in tokens.

CVE-2023-40661

This advisory summarizes automatically reported issues from dynamic analyzers reports in pkcs15-init that are security relevant.

stack buffer overflow in sc_pkcs15_get_lastupdate() in pkcs15init,

heap buffer overflow in setcos_create_key() in pkcs15init,

heap buffer overflow in cosm_new_file() in pkcs15init,

stack buffer overflow in cflex_delete_file() in pkcs15init,

heap buffer overflow in sc_hsm_write_ef() in pkcs15init,

stack buffer overflow while parsing pkcs15 profile files,

stack buffer overflow in muscle driver in pkcs15init, and

stack buffer overflow in cardos driver in pkcs15init.

All of these require physical access to the computer at the time user or administrator would be enrolling the cards (generating keys and loading certificates, other card/token management) operations. The attack requires crafted USB device or smart card that would present the system with specially crafted responses to the APDUs so they are considered a high-complexity and low-severity. This issue is not exploitable just by using a PKCS#11 module as done in most of the end-user deployments.

For Debian 10 buster, these problems have been fixed in version 0.19.0-1+deb10u3.

We recommend that you upgrade your opensc packages.

For the detailed security status of opensc please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'opensc' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"opensc", ver:"0.19.0-1+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opensc-pkcs11", ver:"0.19.0-1+deb10u3", rls:"DEB10"))) {
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
