# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6156.2");
  script_tag(name:"creation_date", value:"2023-06-19 04:09:24 +0000 (Mon, 19 Jun 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-6156-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6156-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6156-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2023598");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd' package(s) announced via the USN-6156-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6156-1 fixed a vulnerability in SSSD. In certain environments, not all
packages ended up being upgraded at the same time, resulting in
authentication failures when the PAM module was being used.

This update fixes the problem. We apologize for the inconvenience.

Original advisory details:

 It was discovered that SSSD incorrrectly sanitized certificate data used in
 LDAP filters. When using this issue in combination with FreeIPA, a remote
 attacker could possibly use this issue to escalate privileges.");

  script_tag(name:"affected", value:"'sssd' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"sssd", ver:"2.2.3-3ubuntu0.12", rls:"UBUNTU20.04 LTS"))) {
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
