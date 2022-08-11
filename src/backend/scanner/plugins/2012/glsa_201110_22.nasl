###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa_201110_22.nasl 11859 2018-10-12 08:53:01Z cfischer $
#
# Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.70785");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0922", "CVE-2009-3229", "CVE-2009-3230", "CVE-2009-3231", "CVE-2009-4034", "CVE-2009-4136", "CVE-2010-0442", "CVE-2010-0733", "CVE-2010-1169", "CVE-2010-1170", "CVE-2010-1447", "CVE-2010-1975", "CVE-2010-3433", "CVE-2010-4015", "CVE-2011-2483");
  script_version("$Revision: 11859 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:40 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201110-22 (postgresql-server postgresql-base)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in the PostgreSQL server and client allow
    remote attacker to conduct several attacks, including the execution of
    arbitrary code and Denial of Service.");
  script_tag(name:"solution", value:"All PostgreSQL 8.2 users should upgrade to the latest 8.2 base version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-base-8.2.22:8.2'


All PostgreSQL 8.3 users should upgrade to the latest 8.3 base version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-base-8.3.16:8.3'


All PostgreSQL 8.4 users should upgrade to the latest 8.4 base version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-base-8.4.9:8.4'


All PostgreSQL 9.0 users should upgrade to the latest 9.0 base version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-base-9.0.5:9.0'


All PostgreSQL 8.2 server users should upgrade to the latest 8.2 server
      version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-server-8.2.22:8.2'


All PostgreSQL 8.3 server users should upgrade to the latest 8.3 server
      version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-server-8.3.16:8.3'


All PostgreSQL 8.4 server users should upgrade to the latest 8.4 server
      version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-server-8.4.9:8.4'


All PostgreSQL 9.0 server users should upgrade to the latest 9.0 server
      version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/postgresql-server-9.0.5:9.0'


The old unsplit PostgreSQL packages have been removed from portage.
      Users still using them are urged to migrate to the new PostgreSQL
      packages as stated above and to remove the old package:

      # emerge --unmerge 'dev-db/postgresql'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-22");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=261223");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=284274");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=297383");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=308063");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=313335");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=320967");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=339935");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=353387");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=384539");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201110-22.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"dev-db/postgresql", unaffected: make_list(), vulnerable: make_list("le 9"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"dev-db/postgresql-server", unaffected: make_list("ge 9.0.5", "rge 8.4.9", "rge 8.3.16", "rge 8.2.22"), vulnerable: make_list("lt 9.0.5"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"dev-db/postgresql-base", unaffected: make_list("ge 9.0.5", "rge 8.4.9", "rge 8.3.16", "rge 8.2.22"), vulnerable: make_list("lt 9.0.5"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
