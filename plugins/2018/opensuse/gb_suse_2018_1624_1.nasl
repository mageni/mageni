###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1624_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for curl openSUSE-SU-2018:1624-1 (curl)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852067");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-1000300", "CVE-2018-1000301");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:41:02 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for curl openSUSE-SU-2018:1624-1 (curl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-06/msg00015.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
  package(s) announced via the openSUSE-SU-2018:1624_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for curl to version 7.60.0 fixes the following issues:

  These security issues were fixed:

  - CVE-2018-1000300: Prevent heap-based buffer overflow when closing down
  an FTP connection with very long server command replies (bsc#1092094).

  - CVE-2018-1000301: Prevent buffer over-read that could have cause reading
  data beyond the end of a heap based buffer used to store downloaded RTSP
  content (bsc#1092098).

  These non-security issues were fixed:

  - Add CURLOPT_HAPROXYPROTOCOL, support for the HAProxy PROXY protocol

  - Add --haproxy-protocol for the command line tool

  - Add CURLOPT_DNS_SHUFFLE_ADDRESSES, shuffle returned IP addresses

  - FTP: fix typo in recursive callback detection for seeking

  - test1208: marked flaky

  - HTTP: make header-less responses still count correct body size

  - user-agent.d:: mention --proxy-header as well

  - http2: fixes typo

  - cleanup: misc typos in strings and comments

  - rate-limit: use three second window to better handle high speeds

  - examples/hiperfifo.c: improved

  - pause: when changing pause state, update socket state

  - curl_version_info.3: fix ssl_version description

  - add_handle/easy_perform: clear errorbuffer on start if set

  - cmake: add support for brotli

  - parsedate: support UT timezone

  - vauth/ntlm.h: fix the #ifdef header guard

  - lib/curl_path.h: added #ifdef header guard

  - vauth/cleartext: fix integer overflow check

  - CURLINFO_COOKIELIST.3: made the example not leak memory

  - cookie.d: mention that '-' as filename means stdin

  - CURLINFO_SSL_VERIFYRESULT.3: fixed the example

  - http2: read pending frames (including GOAWAY) in connection-check

  - timeval: remove compilation warning by casting

  - cmake: avoid warn-as-error during config checks

  - travis-ci: enable -Werror for CMake builds

  - openldap: fix for NULL return from ldap_get_attribute_ber()

  - threaded resolver: track resolver time and set suitable timeout values

  - cmake: Add advapi32 as explicit link library for win32

  - docs: fix CURLINFO_*_T examples use of CURL_FORMAT_CURL_OFF_T

  - test1148: set a fixed locale for the test

  - cookies: when reading from a file, only remove_expired once

  - cookie: store cookies per top-level-domain-specific hash table

  - openssl: RESTORED verify locations when verifypeer==0

  - file: restore old behavior for file:////foo/bar URLs

  - FTP: allow PASV on IPv6 connections when a proxy is being used

  - build-openssl.bat: allow custom paths for VS and perl

  - winbuild: make the clean target work without build-type

  - build-openssl.bat: Refer to VS2017 as VC14.1 instead of VC15

  - curl: r ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"curl on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-debugsource", rpm:"curl-debugsource~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-mini", rpm:"curl-mini~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-mini-debuginfo", rpm:"curl-mini-debuginfo~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-mini-debugsource", rpm:"curl-mini-debugsource~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl-mini-devel", rpm:"libcurl-mini-devel~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4-debuginfo", rpm:"libcurl4-debuginfo~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4-mini", rpm:"libcurl4-mini~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4-mini-debuginfo", rpm:"libcurl4-mini-debuginfo~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl-devel-32bit", rpm:"libcurl-devel-32bit~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4-32bit", rpm:"libcurl4-32bit~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl4-32bit-debuginfo", rpm:"libcurl4-32bit-debuginfo~7.60.0~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
