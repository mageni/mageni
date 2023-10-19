# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6425.3");
  script_cve_id("CVE-2023-4091", "CVE-2023-4154", "CVE-2023-42669", "CVE-2023-42670");
  script_tag(name:"creation_date", value:"2023-10-18 04:08:25 +0000 (Wed, 18 Oct 2023)");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-6425-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU23\.10");

  script_xref(name:"Advisory-ID", value:"USN-6425-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6425-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-6425-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6425-1 fixed vulnerabilities in Samba. This update provides the
corresponding updates for Ubuntu 23.10.

Original advisory details:

 Sri Nagasubramanian discovered that the Samba acl_xattr VFS module
 incorrectly handled read-only files. When Samba is configured to ignore
 system ACLs, a remote attacker could possibly use this issue to truncate
 read-only files. (CVE-2023-4091)

 Andrew Bartlett discovered that Samba incorrectly handled the DirSync
 control. A remote attacker with an RODC DC account could possibly use this
 issue to obtain all domain secrets. (CVE-2023-4154)

 Andrew Bartlett discovered that Samba incorrectly handled the rpcecho
 development server. A remote attacker could possibly use this issue to
 cause Samba to stop responding, resulting in a denial of service.
 (CVE-2023-42669)

 Kirin van der Veer discovered that Samba incorrectly handled certain RPC
 service listeners. A remote attacker could possibly use this issue to cause
 Samba to start multiple incompatible RPC listeners, resulting in a denial
 of service. This issue only affected Ubuntu 22.04 LTS, and Ubuntu 23.04.
 (CVE-2023-42670)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 23.10.");

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

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.18.6+dfsg-1ubuntu2.1", rls:"UBUNTU23.10"))) {
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
