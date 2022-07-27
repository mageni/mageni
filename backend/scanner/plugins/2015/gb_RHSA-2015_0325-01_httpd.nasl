###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for httpd RHSA-2015:0325-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871326");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-03-06 06:50:03 +0100 (Fri, 06 Mar 2015)");
  script_cve_id("CVE-2013-5704", "CVE-2014-3581");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for httpd RHSA-2015:0325-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The httpd packages provide the Apache HTTP Server, a powerful, efficient,
and extensible web server.

A flaw was found in the way httpd handled HTTP Trailer headers when
processing requests using chunked encoding. A malicious client could use
Trailer headers to set additional HTTP headers after header processing was
performed by other modules. This could, for example, lead to a bypass of
header restrictions defined with mod_headers. (CVE-2013-5704)

A NULL pointer dereference flaw was found in the way the mod_cache httpd
module handled Content-Type headers. A malicious HTTP server could cause
the httpd child process to crash when the Apache HTTP server was configured
to proxy to a server with caching enabled. (CVE-2014-3581)

This update also fixes the following bugs:

  * Previously, the mod_proxy_fcgi Apache module always kept the back-end
connections open even when they should have been closed. As a consequence,
the number of open file descriptors was increasing over the time. With this
update, mod_proxy_fcgi has been fixed to check the state of the back-end
connections, and it closes the idle back-end connections as expected.
(BZ#1168050)

  * An integer overflow occurred in the ab utility when a large request count
was used. Consequently, ab terminated unexpectedly with a segmentation
fault while printing statistics after the benchmark. This bug has been
fixed, and ab no longer crashes in this scenario. (BZ#1092420)

  * Previously, when httpd was running in the foreground and the user pressed
Ctrl+C to interrupt the httpd processes, a race condition in signal
handling occurred. The SIGINT signal was sent to all children followed by
SIGTERM from the main process, which interrupted the SIGINT handler.
Consequently, the affected processes became unresponsive or terminated
unexpectedly. With this update, the SIGINT signals in the child processes
are ignored, and httpd no longer hangs or crashes in this scenario.
(BZ#1131006)

In addition, this update adds the following enhancements:

  * With this update, the mod_proxy module of the Apache HTTP Server supports
the Unix Domain Sockets (UDS). This allows mod_proxy back ends to listen on
UDS sockets instead of TCP sockets, and as a result, mod_proxy can be used
to connect UDS back ends. (BZ#1168081)

  * This update adds support for using the SetHandler directive together with
the mod_proxy module. As a result, it is possible to configure SetHandler
to use proxy for incoming requests, for example, in the following format:
SetHandler 'proxy:fcgi://127.0.0.1:9000'. (BZ#1136290)

  * The htaccess API changes introduced in httpd 2.4.7  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"httpd on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-March/msg00022.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.4.6~31.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.4.6~31.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.4.6~31.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.4.6~31.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.4.6~31.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.4.6~31.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
