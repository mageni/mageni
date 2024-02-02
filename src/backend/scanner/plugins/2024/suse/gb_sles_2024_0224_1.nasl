# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0224.1");
  script_cve_id("CVE-2022-45047", "CVE-2023-48795");
  script_tag(name:"creation_date", value:"2024-01-26 04:21:21 +0000 (Fri, 26 Jan 2024)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-18 18:09:17 +0000 (Fri, 18 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0224-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0224-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240224-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-parent, apache-sshd' package(s) announced via the SUSE-SU-2024:0224-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache-parent, apache-sshd fixes the following issues:
apache-parent was updated from version 28 to 31:

Version 31:
New Features:
Added maven-checkstyle-plugin to pluginManagement


Improvements:
Set minimalMavenBuildVersion to 3.6.3 - the minimum
 used by plugins Using an SPDX identifier as the license name is
 recommended by Maven Use properties to define the versions of plugins


Bugs fixed:
Updated documentation for previous changes



apache-sshd was updated from version 2.7.0 to 2.12.0:

Security issues fixed:
CVE-2023-48795: Implemented OpenSSH 'strict key exchange' protocol in apache-sshd version 2.12.0 (bsc#1218189)

CVE-2022-45047: Java unsafe deserialization vulnerability fixed in apache-sshd version 2.9.2 (bsc#1205463)


Other changes in version 2.12.0:

Bugs fixed:
SCP client fails silently when error signalled due to missing file or lacking permissions Ignore unknown key types from agent or in OpenSSH host keys extension


New Features:
Support GIT protocol-v2


Other changes in version 2.11.0:
Bugs fixed:
Added configurable timeout(s) to DefaultSftpClient Compare file keys in ModifiableFileWatcher.
Fixed channel pool in SftpFileSystem.
Use correct default OpenOptions in SftpFileSystemProvider.newFileChannel().
Use correct lock modes for SFTP FileChannel.lock().
ScpClient: support issuing commands to a server that uses a non-UTF-8 locale.
SftpInputStreamAsync: fix reporting EOF on zero-length reads.
Work-around a bug in WS_FTP <= 12.9 SFTP clients.
(Regression in 2.10.0) SFTP performance fix: override FilterOutputStream.write(byte[], int, int).
Fixed a race condition to ensure SSH_MSG_CHANNEL_EOF is always sent before SSH_MSG_CHANNEL_CLOSE.
Fixed error handling while flushing queued packets at end of KEX.
Fixed wrong log level on closing an Nio2Session.
Fixed detection of Android O/S from system properties.
Consider all applicable host keys from the known_hosts files.
SftpFileSystem: do not close user session.
ChannelAsyncOutputStream: remove write future when done.
SSHD-1332 (Regression in 2.10.0) Resolve ~ in IdentityFile file names in HostConfigEntry.


New Features:
Use KeepAliveHandler global request instance in client as well Publish snapshot maven artifacts to the Apache Snapshots maven repository.
Bundle sshd-contrib has support classes for the HAProxy protocol V2.


Other changes in version 2.10.0:
Bugs fixed:
Connection attempt not canceled when a connection timeout occurs Possible OOM in ChannelPipedInputStream SftpRemotePathChannel.transferFrom(...) ignores position argument Rooted file system can leak informations Failed to establish an SSH connection because the server identifier exceeds the int range


Improvements:
Password in clear in SSHD server's logs


Other changes in version 2.9.2:
Bugs fixed:
SFTP worker threads got stuck while processing PUT methods against one specific SFTP server Use the maximum packet size of the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'apache-parent, apache-sshd' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"apache-sshd", rpm:"apache-sshd~2.12.0~150200.5.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"apache-sshd", rpm:"apache-sshd~2.12.0~150200.5.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"apache-sshd", rpm:"apache-sshd~2.12.0~150200.5.8.1", rls:"SLES15.0SP4"))) {
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
