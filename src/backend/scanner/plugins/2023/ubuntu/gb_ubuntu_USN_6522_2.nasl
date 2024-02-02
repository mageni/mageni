# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6522.2");
  script_cve_id("CVE-2022-41877", "CVE-2023-39352", "CVE-2023-39356");
  script_tag(name:"creation_date", value:"2023-12-08 04:09:09 +0000 (Fri, 08 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-07 16:10:53 +0000 (Thu, 07 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6522-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6522-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6522-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp2' package(s) announced via the USN-6522-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6522-1 fixed several vulnerabilities in FreeRDP. This update provides
the corresponding update for Ubuntu 18.04 LTS.
Original advisory details:

 It was discovered that FreeRDP incorrectly handled drive redirection. If a
 user were tricked into connection to a malicious server, a remote attacker
 could use this issue to cause FreeRDP to crash, resulting in a denial of
 service, or possibly obtain sensitive information. (CVE-2022-41877)

 It was discovered that FreeRDP incorrectly handled certain surface updates.
 A remote attacker could use this issue to cause FreeRDP to crash, resulting
 in a denial of service, or possibly execute arbitrary code.
 (CVE-2023-39352, CVE-2023-39356)");

  script_tag(name:"affected", value:"'freerdp2' package(s) on Ubuntu 18.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.2.0+dfsg1-0ubuntu0.18.04.4+esm2", rls:"UBUNTU18.04 LTS"))) {
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
