# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5511");
  script_cve_id("CVE-2021-34434", "CVE-2023-0809", "CVE-2023-28366", "CVE-2023-3592");
  script_tag(name:"creation_date", value:"2023-10-02 07:56:43 +0000 (Mon, 02 Oct 2023)");
  script_version("2023-10-06T05:06:29+0000");
  script_tag(name:"last_modification", value:"2023-10-06 05:06:29 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-04 17:00:00 +0000 (Wed, 04 Oct 2023)");

  script_name("Debian: Security Advisory (DSA-5511)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5511");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5511");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5511");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mosquitto");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mosquitto' package(s) announced via the DSA-5511 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in mosquitto, a MQTT compatible message broker, which may be abused for a denial of service attack.

CVE-2021-34434

In Eclipse Mosquitto when using the dynamic security plugin, if the ability for a client to make subscriptions on a topic is revoked when a durable client is offline, then existing subscriptions for that client are not revoked.

CVE-2023-0809

Fix excessive memory being allocated based on malicious initial packets that are not CONNECT packets.

CVE-2023-3592

Fix memory leak when clients send v5 CONNECT packets with a will message that contains invalid property types.

CVE-2023-28366

The broker in Eclipse Mosquitto has a memory leak that can be abused remotely when a client sends many QoS 2 messages with duplicate message IDs, and fails to respond to PUBREC commands. This occurs because of mishandling of EAGAIN from the libc send function.

Additionally CVE-2021-41039 has been fixed for Debian 11 Bullseye.

CVE-2021-41039

An MQTT v5 client connecting with a large number of user-property properties could cause excessive CPU usage, leading to a loss of performance and possible denial of service.

For the oldstable distribution (bullseye), these problems have been fixed in version 2.0.11-1+deb11u1.

For the stable distribution (bookworm), these problems have been fixed in version 2.0.11-1.2+deb12u1.

We recommend that you upgrade your mosquitto packages.

For the detailed security status of mosquitto please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'mosquitto' package(s) on Debian 11, Debian 12.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libmosquitto-dev", ver:"2.0.11-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmosquitto1", ver:"2.0.11-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmosquittopp-dev", ver:"2.0.11-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmosquittopp1", ver:"2.0.11-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mosquitto", ver:"2.0.11-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mosquitto-clients", ver:"2.0.11-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mosquitto-dev", ver:"2.0.11-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"libmosquitto-dev", ver:"2.0.11-1.2+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmosquitto1", ver:"2.0.11-1.2+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmosquittopp-dev", ver:"2.0.11-1.2+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmosquittopp1", ver:"2.0.11-1.2+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mosquitto", ver:"2.0.11-1.2+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mosquitto-clients", ver:"2.0.11-1.2+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mosquitto-dev", ver:"2.0.11-1.2+deb12u1", rls:"DEB12"))) {
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
