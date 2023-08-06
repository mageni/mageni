# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827937");
  script_version("2023-07-28T16:09:07+0000");
  script_cve_id("CVE-2023-32732");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-26 01:13:21 +0000 (Wed, 26 Jul 2023)");
  script_name("Fedora: Security Advisory for grpc (FEDORA-2023-6cad6e5003)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-6cad6e5003");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VWE44J5FG7THHL7XVEVTNIGEYBNKJBLL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grpc'
  package(s) announced via the FEDORA-2023-6cad6e5003 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"gRPC is a modern open source high performance RPC framework that can run in any
environment. It can efficiently connect services in and across data centers
with pluggable support for load balancing, tracing, health checking and
authentication. It is also applicable in last mile of distributed computing to
connect devices, mobile applications and browsers to backend services.

The main usage scenarios:

   Efficiently connecting polyglot services in microservices style
    architecture
   Connecting mobile devices, browser clients to backend services
   Generating efficient client libraries

Core Features that make it awesome:

   Idiomatic client libraries in 10 languages
   Highly efficient on wire and with a simple service definition framework
   Bi-directional streaming with http/2 based transport
   Pluggable auth, tracing, load balancing and health checking

This package provides the shared C core library.");

  script_tag(name:"affected", value:"'grpc' package(s) on Fedora 37.");

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

if(release == "FC37") {

  if(!isnull(res = isrpmvuln(pkg:"grpc", rpm:"grpc~1.48.4~8.fc37", rls:"FC37"))) {
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