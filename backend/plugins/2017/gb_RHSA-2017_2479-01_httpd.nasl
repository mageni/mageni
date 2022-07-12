###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2479-01_httpd.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for httpd RHSA-2017:2479-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871882");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-16 07:29:18 +0200 (Wed, 16 Aug 2017)");
  script_cve_id("CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7668", "CVE-2017-7679",
                "CVE-2017-9788");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for httpd RHSA-2017:2479-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The httpd packages provide the Apache HTTP
  Server, a powerful, efficient, and extensible web server. Security Fix(es): * It
  was discovered that the httpd's mod_auth_digest module did not properly
  initialize memory before using it when processing certain headers related to
  digest authentication. A remote attacker could possibly use this flaw to
  disclose potentially sensitive information or cause httpd child process to crash
  by sending specially crafted requests to a server. (CVE-2017-9788) * It was
  discovered that the use of httpd's ap_get_basic_auth_pw() API function outside
  of the authentication phase could lead to authentication bypass. A remote
  attacker could possibly use this flaw to bypass required authentication if the
  API was used incorrectly by one of the modules used by httpd. (CVE-2017-3167) *
  A NULL pointer dereference flaw was found in the httpd's mod_ssl module. A
  remote attacker could use this flaw to cause an httpd child process to crash if
  another module used by httpd called a certain API function during the processing
  of an HTTPS request. (CVE-2017-3169) * A buffer over-read flaw was found in the
  httpd's ap_find_token() function. A remote attacker could use this flaw to cause
  httpd child process to crash via a specially crafted HTTP request.
  (CVE-2017-7668) * A buffer over-read flaw was found in the httpd's mod_mime
  module. A user permitted to modify httpd's MIME configuration could use this
  flaw to cause httpd child process to crash. (CVE-2017-7679)");
  script_tag(name:"affected", value:"httpd on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00062.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.4.6~67.el7_4.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.4.6~67.el7_4.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.4.6~67.el7_4.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.4.6~67.el7_4.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.4.6~67.el7_4.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_session", rpm:"mod_session~2.4.6~67.el7_4.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.4.6~67.el7_4.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
