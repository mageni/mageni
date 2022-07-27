# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0374");
  script_cve_id("CVE-2021-21295", "CVE-2021-21409");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-31T07:41:30+0000");
  script_tag(name:"last_modification", value:"2022-01-31 07:41:30 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-09 18:15:00 +0000 (Fri, 09 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0374)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0374");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0374.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28985");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4885");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netty' package(s) announced via the MGASA-2021-0374 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Netty (io.netty:netty-codec-http2) before version 4.1.60.Final there is a
vulnerability that enables request smuggling. If a Content-Length header is
present in the original HTTP/2 request, the field is not validated by
`Http2MultiplexHandler` as it is propagated up. This is fine as long as the
request is not proxied through as HTTP/1.1. If the request comes in as an
HTTP/2 stream, gets converted into the HTTP/1.1 domain objects (`HttpRequest`,
`HttpContent`, etc.) via `Http2StreamFrameToHttpObjectCodec `and then sent up
to the child channel's pipeline and proxied through a remote peer as HTTP/1.1
this may result in request smuggling. In a proxy case, users may assume the
content-length is validated somehow, which is not the case. If the request is
forwarded to a backend channel that is a HTTP/1.1 connection, the Content-
Length now has meaning and needs to be checked. An attacker can smuggle
requests inside the body as it gets downgraded from HTTP/2 to HTTP/1.1. For
an example attack refer to the linked GitHub Advisory. Users are only affected
if all of this is true: `HTTP2MultiplexCodec` or `Http2FrameCodec` is used,
`Http2StreamFrameToHttpObjectCodec` is used to convert to HTTP/1.1 objects,
and these HTTP/1.1 objects are forwarded to another remote peer. This has been
patched in 4.1.60.Final As a workaround, the user can do the validation by
themselves by implementing a custom `ChannelInboundHandler` that is put in the
`ChannelPipeline` behind `Http2StreamFrameToHttpObjectCodec`
(CVE-2021-21295).

In Netty (io.netty:netty-codec-http2) before version 4.1.61.Final there is a
vulnerability that enables request smuggling. The content-length header is not
correctly validated if the request only uses a single Http2HeaderFrame with
the endStream set to true. This could lead to request smuggling if the
request is proxied to a remote peer and translated to HTTP/1.1. This is a
followup of GHSA-wm47-8v5p-wjpj/CVE-2021-21295 which did miss to fix this one
case. This was fixed as part of 4.1.61.Final
(CVE-2021-21409).");

  script_tag(name:"affected", value:"'netty' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"netty", rpm:"netty~4.1.51~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-javadoc", rpm:"netty-javadoc~4.1.51~1.2.mga8", rls:"MAGEIA8"))) {
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
