# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0340");
  script_cve_id("CVE-2023-3961", "CVE-2023-4091", "CVE-2023-42669");
  script_tag(name:"creation_date", value:"2023-12-06 04:12:00 +0000 (Wed, 06 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-13 18:48:45 +0000 (Mon, 13 Nov 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0340)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0340");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0340.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32560");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28606");
  script_xref(name:"URL", value:"https://lwn.net/Articles/952257/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the MGASA-2023-0340 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the security issues below.

A path traversal vulnerability was identified in Samba when processing
client pipe names connecting to Unix domain sockets within a private
directory. Samba typically uses this mechanism to connect SMB clients to
remote procedure call (RPC) services like SAMR LSA or SPOOLSS, which
Samba initiates on demand. However, due to inadequate sanitization of
incoming client pipe names, allowing a client to send a pipe name
containing Unix directory traversal characters (../). This could result
in SMB clients connecting as root to Unix domain sockets outside the
private directory. If an attacker or client managed to send a pipe name
resolving to an external service using an existing Unix domain socket,
it could potentially lead to unauthorized access to the service and
consequential adverse events, including compromise or service crashes.
(CVE-2023-3961)

A vulnerability was discovered in Samba, where the flaw allows SMB
clients to truncate files, even with read-only permissions when the
Samba VFS module 'acl_xattr' is configured with 'acl_xattr:ignore system
acls = yes'. The SMB protocol allows opening files when the client
requests read-only access but then implicitly truncates the opened file
to 0 bytes if the client specifies a separate OVERWRITE create
disposition request. The issue arises in configurations that bypass
kernel file system permissions checks, relying solely on Samba's
permissions. (CVE-2023-4091)

A vulnerability was found in Samba's 'rpcecho' development server, a
non-Windows RPC server used to test Samba's DCE/RPC stack elements. This
indefinitely. The issue arises because the 'rpcecho' service operates
with only one worker in the main RPC task, allowing calls to the
'rpcecho' server to be blocked for a specified time, causing service
disruptions. This disruption is triggered by a 'sleep()' call in the
'dcesrv_echo_TestSleep()' function under specific conditions.
Authenticated users or attackers can exploit this vulnerability to make
calls to the 'rpcecho' server, requesting it to block for a specified
duration, effectively disrupting most services and leading to a complete
denial of service on the AD DC. The DoS affects all other services as
'rpcecho' runs in the main RPC task. (CVE-2023-42669)

Apart from the new version, a Recommends for cifs-client was added in
samba-client for [link moved to references]");

  script_tag(name:"affected", value:"'samba' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"ctdb", rpm:"ctdb~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba-dc0", rpm:"lib64samba-dc0~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba-devel", rpm:"lib64samba-devel~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba-test0", rpm:"lib64samba-test0~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64samba1", rpm:"lib64samba1~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient-devel", rpm:"lib64smbclient-devel~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wbclient-devel", rpm:"lib64wbclient-devel~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wbclient0", rpm:"lib64wbclient0~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-dc0", rpm:"libsamba-dc0~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-devel", rpm:"libsamba-devel~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-test0", rpm:"libsamba-test0~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba1", rpm:"libsamba1~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-samba", rpm:"python3-samba~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dc", rpm:"samba-dc~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-krb5-printing", rpm:"samba-krb5-printing~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-test", rpm:"samba-test~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-usershares", rpm:"samba-usershares~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-krb5-locator", rpm:"samba-winbind-krb5-locator~4.17.12~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-modules", rpm:"samba-winbind-modules~4.17.12~1.mga9", rls:"MAGEIA9"))) {
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
