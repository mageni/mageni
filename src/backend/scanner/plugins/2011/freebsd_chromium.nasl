###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_chromium.nasl 14170 2019-03-14 09:24:12Z cfischer $
#
# Auto generated from VID 6887828f-0229-11e0-b84d-00262d5ed8ee
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
  script_oid("1.3.6.1.4.1.25623.1.0.68696");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 14170 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
  script_cve_id("CVE-2011-1290", "CVE-2011-1291", "CVE-2011-1292", "CVE-2011-1293", "CVE-2011-1294", "CVE-2011-1295", "CVE-2011-1296", "CVE-2011-1301", "CVE-2011-1302", "CVE-2011-1303", "CVE-2011-1304", "CVE-2011-1305", "CVE-2011-1434", "CVE-2011-1435", "CVE-2011-1436", "CVE-2011-1437", "CVE-2011-1438", "CVE-2011-1439", "CVE-2011-1440", "CVE-2011-1441", "CVE-2011-1442", "CVE-2011-1443", "CVE-2011-1444", "CVE-2011-1445", "CVE-2011-1446", "CVE-2011-1447", "CVE-2011-1448", "CVE-2011-1449", "CVE-2011-1450", "CVE-2011-1451", "CVE-2011-1452", "CVE-2011-1454", "CVE-2011-1455", "CVE-2011-1456", "CVE-2011-1799", "CVE-2011-1800", "CVE-2011-1801", "CVE-2011-1804", "CVE-2011-1806", "CVE-2011-1807", "CVE-2011-1808", "CVE-2011-1809", "CVE-2011-1810", "CVE-2011-1811", "CVE-2011-1812", "CVE-2011-1813", "CVE-2011-1814", "CVE-2011-1815", "CVE-2011-1816", "CVE-2011-1817", "CVE-2011-1818", "CVE-2011-1819", "CVE-2011-2332", "CVE-2011-2342", "CVE-2011-2345", "CVE-2011-2346", "CVE-2011-2347", "CVE-2011-2348", "CVE-2011-2349", "CVE-2011-2350", "CVE-2011-2351", "CVE-2011-2358", "CVE-2011-2359", "CVE-2011-2360", "CVE-2011-2361", "CVE-2011-2782", "CVE-2011-2783", "CVE-2011-2784", "CVE-2011-2785", "CVE-2011-2786", "CVE-2011-2787", "CVE-2011-2788", "CVE-2011-2789", "CVE-2011-2790", "CVE-2011-2791", "CVE-2011-2792", "CVE-2011-2793", "CVE-2011-2794", "CVE-2011-2795", "CVE-2011-2796", "CVE-2011-2797", "CVE-2011-2798", "CVE-2011-2799", "CVE-2011-2800", "CVE-2011-2801", "CVE-2011-2802", "CVE-2011-2803", "CVE-2011-2804", "CVE-2011-2805", "CVE-2011-2818", "CVE-2011-2819", "CVE-2011-2821", "CVE-2011-2823", "CVE-2011-2824", "CVE-2011-2825", "CVE-2011-2826", "CVE-2011-2827", "CVE-2011-2828", "CVE-2011-2829", "CVE-2011-2834", "CVE-2011-2835", "CVE-2011-2836", "CVE-2011-2837", "CVE-2011-2838", "CVE-2011-2839", "CVE-2011-2840", "CVE-2011-2841", "CVE-2011-2842", "CVE-2011-2843", "CVE-2011-2844", "CVE-2011-2845", "CVE-2011-2846", "CVE-2011-2847", "CVE-2011-2848", "CVE-2011-2849", "CVE-2011-2850", "CVE-2011-2851", "CVE-2011-2852", "CVE-2011-2853", "CVE-2011-2854", "CVE-2011-2855", "CVE-2011-2856", "CVE-2011-2857", "CVE-2011-2858", "CVE-2011-2859", "CVE-2011-2860", "CVE-2011-2861", "CVE-2011-2862", "CVE-2011-2864", "CVE-2011-2874", "CVE-2011-2875", "CVE-2011-2876", "CVE-2011-2877", "CVE-2011-2878", "CVE-2011-2879", "CVE-2011-2880", "CVE-2011-2881", "CVE-2011-3234", "CVE-2011-3873", "CVE-2011-3873", "CVE-2011-3875", "CVE-2011-3876", "CVE-2011-3877", "CVE-2011-3878", "CVE-2011-3879", "CVE-2011-3880", "CVE-2011-3881", "CVE-2011-3882", "CVE-2011-3883", "CVE-2011-3884", "CVE-2011-3885", "CVE-2011-3886", "CVE-2011-3887", "CVE-2011-3888", "CVE-2011-3889", "CVE-2011-3890", "CVE-2011-3891", "CVE-2011-3892", "CVE-2011-3893", "CVE-2011-3894", "CVE-2011-3895", "CVE-2011-3896", "CVE-2011-3897", "CVE-2011-3898", "CVE-2011-3900");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: chromium");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/6887828f-0229-11e0-b84d-00262d5ed8ee.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"chromium");
if(!isnull(bver) && revcomp(a:bver, b:"8.0.552.215")<0) {
  txt += 'Package chromium version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}