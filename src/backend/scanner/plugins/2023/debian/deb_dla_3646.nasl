# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3646");
  script_cve_id("CVE-2023-34058", "CVE-2023-34059");
  script_tag(name:"creation_date", value:"2023-11-07 04:19:45 +0000 (Tue, 07 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-07 21:07:45 +0000 (Tue, 07 Nov 2023)");

  script_name("Debian: Security Advisory (DLA-3646-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3646-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3646-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/open-vm-tools");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'open-vm-tools' package(s) announced via the DLA-3646-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brief introduction

CVE-2023-34058

A file descriptor hijack vulnerability was found in the vmware-user-suid-wrapper command. A malicious actor with non-root privileges might have been able to hijack the /dev/uinput file descriptor allowing them to simulate user inputs.

CVE-2023-34059

A SAML Token Signature Bypass vulnerability was found. A malicious actor that has been granted Guest Operation Privileges in a target virtual machine might have been able to elevate their privileges if that target virtual machine has been assigned a more privileged Guest Alias.

For Debian 10 buster, these problems have been fixed in version 2:10.3.10-1+deb10u6.

We recommend that you upgrade your open-vm-tools packages.

For the detailed security status of open-vm-tools please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'open-vm-tools' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"open-vm-tools", ver:"2:10.3.10-1+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"open-vm-tools-desktop", ver:"2:10.3.10-1+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"open-vm-tools-dev", ver:"2:10.3.10-1+deb10u6", rls:"DEB10"))) {
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
