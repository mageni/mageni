# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0320");
  script_cve_id("CVE-2023-40225");
  script_tag(name:"creation_date", value:"2023-11-21 04:12:14 +0000 (Tue, 21 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-18 20:03:17 +0000 (Fri, 18 Aug 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0320)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0320");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0320.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32319");
  script_xref(name:"URL", value:"https://www.haproxy.org/download/2.8/src/CHANGELOG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy' package(s) announced via the MGASA-2023-0320 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Haproxy has fixed security and other issues in last upstream version
2.8.3 of branch 2.8

Default user access are now commented out to prevent local action
possible exploit and prevent further rpmnew on future updates.

Use a check script to have config check result in error log on failure.

Fix corruption with non empty access log.

Fixed major bug list:
- quic: Really ignore malformed ACK frames
- http-ana: Get a fresh trash buffer for each header value replacement
- h3: reject header values containing invalid chars
- http: reject any empty content-length header value (CVE-2023-40225)

Fixed medium bug list:
- quic: fix tasklet_wakeup loop on connection closing
- stconn: Update stream expiration date on blocked sends
- stconn: Wake applets on sending path if there is a pending shutdown
- stconn: Don't block sends if there is a pending shutdown
- h1-htx: Ensure chunked parsing with full output buffer
- applet: Fix API for function to push new data in channels buffer
- stconn: Report read activity when a stream is attached to front SC
- applet: Report an error if applet request more room on aborted SC
- stconn/stream: Forward shutdown on write timeout
- stconn: Always update stream's expiration date after I/O
- capabilities: enable support for Linux capabilities
- sink: invalid server list in sink_new_from_logsrv()
- log: improper use of logsrv->maxlen for buffer targets
- quic: token IV was not computed using a strong secret
- quic: missing check of dcid for init pkt including a token
- quic: timestamp shared in token was using internal time clock
- hlua_fcn/queue: bad pop_wait sequencing
- listener: Acquire proxy's lock in relax_listener() if necessary
- h3: Properly report a C-L header was found to the HTX start-line
- h3: Be sure to handle fin bit on the last DATA frame
- bwlim: Reset analyse expiration date when then channel analyse ends
- quic: consume contig space on requeue datagram");

  script_tag(name:"affected", value:"'haproxy' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~2.8.3~9.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-noquic", rpm:"haproxy-noquic~2.8.3~9.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-quic", rpm:"haproxy-quic~2.8.3~9.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-utils", rpm:"haproxy-utils~2.8.3~9.mga9", rls:"MAGEIA9"))) {
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
