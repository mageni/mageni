# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5193.3");
  script_cve_id("CVE-2021-4008", "CVE-2021-4009", "CVE-2021-4011");
  script_tag(name:"creation_date", value:"2023-07-28 04:09:30 +0000 (Fri, 28 Jul 2023)");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-30 16:37:00 +0000 (Wed, 30 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5193-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5193-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5193-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-server-hwe-16.04' package(s) announced via the USN-5193-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5193-1 fixed several vulnerabilities in X.Org. This update provides
the corresponding update for Ubuntu 16.04 ESM.

Original advisory details:

 Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled
 certain inputs. An attacker could use this issue to cause the server to
 crash, resulting in a denial of service, or possibly execute arbitrary
 code and escalate privileges.");

  script_tag(name:"affected", value:"'xorg-server-hwe-16.04' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core-hwe-16.04", ver:"2:1.19.6-1ubuntu4.1~16.04.6+esm5", rls:"UBUNTU16.04 LTS"))) {
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
