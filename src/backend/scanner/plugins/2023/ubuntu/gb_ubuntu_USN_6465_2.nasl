# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6465.2");
  script_cve_id("CVE-2023-31083", "CVE-2023-3772");
  script_tag(name:"creation_date", value:"2023-11-01 13:52:44 +0000 (Wed, 01 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-02 18:19:06 +0000 (Tue, 02 May 2023)");

  script_name("Ubuntu: Security Advisory (USN-6465-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6465-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6465-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi' package(s) announced via the USN-6465-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yu Hao and Weiteng Chen discovered that the Bluetooth HCI UART driver in
the Linux kernel contained a race condition, leading to a null pointer
dereference vulnerability. A local attacker could use this to cause a
denial of service (system crash). (CVE-2023-31083)

Lin Ma discovered that the Netlink Transformation (XFRM) subsystem in the
Linux kernel contained a null pointer dereference vulnerability in some
situations. A local privileged attacker could use this to cause a denial of
service (system crash). (CVE-2023-3772)");

  script_tag(name:"affected", value:"'linux-raspi' package(s) on Ubuntu 22.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1042-raspi", ver:"5.15.0-1042.45", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.15.0.1042.40", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.15.0.1042.40", rls:"UBUNTU22.04 LTS"))) {
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
