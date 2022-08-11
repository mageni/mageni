###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_1831_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for haproxy openSUSE-SU-2015:1831-1 (haproxy)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851120");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-28 07:18:30 +0100 (Wed, 28 Oct 2015)");
  script_cve_id("CVE-2015-3281");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for haproxy openSUSE-SU-2015:1831-1 (haproxy)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"haproxy was updated to fix two security issues.

  These security issues were fixed:

  - CVE-2015-3281: The buffer_slow_realign function in HAProxy did not
  properly realign a buffer that is used for pending outgoing data, which
  allowed remote attackers to obtain sensitive information (uninitialized
  memory contents of previous requests) via a crafted request (bsc#937042).

  - Changed DH parameters to prevent Logjam attack.

  These non-security issues were fixed:

  - BUG/MAJOR: buffers: make the buffer_slow_realign() function respect
  output data

  - BUG/MINOR: ssl: fix smp_fetch_ssl_fc_session_id

  - MEDIUM: ssl: replace standards DH groups with custom ones

  - BUG/MEDIUM: ssl: fix tune.ssl.default-dh-param value being overwritten

  - MINOR: ssl: add a destructor to free allocated SSL resources

  - BUG/MINOR: ssl: Display correct filename in error message

  - MINOR: ssl: load certificates in alphabetical order

  - BUG/MEDIUM: checks: fix conflicts between agent checks and ssl
  healthchecks

  - BUG/MEDIUM: ssl: force a full GC in case of memory shortage

  - BUG/MEDIUM: ssl: fix bad ssl context init can cause segfault in case of
  OOM.

  - BUG/MINOR: ssl: correctly initialize ssl ctx for invalid certificates

  - MINOR: ssl: add statement to force some ssl options in global.

  - MINOR: ssl: add fetchs 'ssl_c_der' and 'ssl_f_der' to return DER
  formatted certs");
  script_tag(name:"affected", value:"haproxy on openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~1.5.5~3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"haproxy-debuginfo", rpm:"haproxy-debuginfo~1.5.5~3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"haproxy-debugsource", rpm:"haproxy-debugsource~1.5.5~3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
