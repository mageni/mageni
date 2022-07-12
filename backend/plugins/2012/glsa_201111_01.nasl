###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa_201111_01.nasl 11859 2018-10-12 08:53:01Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.70790");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-2345", "CVE-2011-2346", "CVE-2011-2347", "CVE-2011-2348", "CVE-2011-2349", "CVE-2011-2350", "CVE-2011-2351", "CVE-2011-2834", "CVE-2011-2835", "CVE-2011-2837", "CVE-2011-2838", "CVE-2011-2839", "CVE-2011-2840", "CVE-2011-2841", "CVE-2011-2843", "CVE-2011-2844", "CVE-2011-2845", "CVE-2011-2846", "CVE-2011-2847", "CVE-2011-2848", "CVE-2011-2849", "CVE-2011-2850", "CVE-2011-2851", "CVE-2011-2852", "CVE-2011-2853", "CVE-2011-2854", "CVE-2011-2855", "CVE-2011-2856", "CVE-2011-2857", "CVE-2011-2858", "CVE-2011-2859", "CVE-2011-2860", "CVE-2011-2861", "CVE-2011-2862", "CVE-2011-2864", "CVE-2011-2874", "CVE-2011-3234", "CVE-2011-3873", "CVE-2011-3875", "CVE-2011-3876", "CVE-2011-3877", "CVE-2011-3878", "CVE-2011-3879", "CVE-2011-3880", "CVE-2011-3881", "CVE-2011-3882", "CVE-2011-3883", "CVE-2011-3884", "CVE-2011-3885", "CVE-2011-3886", "CVE-2011-3887", "CVE-2011-3888", "CVE-2011-3889", "CVE-2011-3890", "CVE-2011-3891");
  script_version("$Revision: 11859 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:53:01 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:40 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201111-01 (chromium v8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been reported in Chromium and V8,
    some of which may allow execution of arbitrary code and local root
    privilege escalation.");
  script_tag(name:"solution", value:"All Chromium users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/chromium-15.0.874.102'


All V8 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/v8-3.5.10.22'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201111-01");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=351525");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=353626");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=354121");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=356933");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=357963");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=358581");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=360399");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=363629");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=365125");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=366335");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=367013");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=368649");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=370481");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=373451");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=373469");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=377475");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=377629");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=380311");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=380897");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=381713");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=383251");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=385649");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=388461");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/03/chrome-stable-release.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/03/stable-and-beta-channel-updates.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/04/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/04/chrome-stable-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/05/beta-and-stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/05/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/05/stable-channel-update_24.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/06/stable-channel-update_28.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/06/chrome-stable-release.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/08/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/08/stable-channel-update_22.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/09/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/09/stable-channel-update_16.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/10/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/10/chrome-stable-release.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/01/chrome-stable-release.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/02/stable-channel-update_28.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/02/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/02/stable-channel-update_08.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201111-01.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"www-client/chromium", unaffected: make_list("ge 15.0.874.102"), vulnerable: make_list("lt 15.0.874.102"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"dev-lang/v8", unaffected: make_list("ge 3.5.10.22"), vulnerable: make_list("lt 3.5.10.22"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
