# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2264");
  script_cve_id("CVE-2022-48337", "CVE-2022-48338", "CVE-2022-48339");
  script_tag(name:"creation_date", value:"2023-07-04 04:14:06 +0000 (Tue, 04 Jul 2023)");
  script_version("2023-07-04T05:05:35+0000");
  script_tag(name:"last_modification", value:"2023-07-04 05:05:35 +0000 (Tue, 04 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-02 16:08:00 +0000 (Thu, 02 Mar 2023)");

  script_name("Huawei EulerOS: Security Advisory for emacs (EulerOS-SA-2023-2264)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2264");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2264");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'emacs' package(s) announced via the EulerOS-SA-2023-2264 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in GNU Emacs through 28.2. htmlfontify.el has a command injection vulnerability. In the hfy-istext-command function, the parameter file and parameter srcdir come from external input, and parameters are not escaped. If a file name or directory name contains shell metacharacters, code may be executed.(CVE-2022-48339)

An issue was discovered in GNU Emacs through 28.2. In ruby-mode.el, the ruby-find-library-file function has a local command injection vulnerability. The ruby-find-library-file function is an interactive function, and bound to C-c C-f. Inside the function, the external command gem is called through shell-command-to-string, but the feature-name parameters are not escaped. Thus, malicious Ruby source files may cause commands to be executed.(CVE-2022-48338)

GNU Emacs through 28.2 allows attackers to execute commands via shell metacharacters in the name of a source-code file, because lib-src/etags.c uses the system C library function in its implementation of the etags program. For example, a victim may use the 'etags -u *' command (suggested in the etags documentation) in a situation where the current working directory has contents that depend on untrusted input.(CVE-2022-48337)");

  script_tag(name:"affected", value:"'emacs' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"emacs-filesystem", rpm:"emacs-filesystem~27.2~3.h4.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
