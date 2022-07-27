###############################################################################
# OpenVAS Vulnerability Test
# $Id: glsa-201310-12.nasl 12128 2018-10-26 13:35:25Z cfischer $
#
# Gentoo Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121050");
  script_version("$Revision: 12128 $");
  script_tag(name:"creation_date", value:"2015-09-29 11:26:08 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 15:35:25 +0200 (Fri, 26 Oct 2018) $");
  script_name("Gentoo Security Advisory GLSA 201310-12");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in FFmpeg. Please review the CVE identifiers and FFmpeg changelogs referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201310-12");
  script_cve_id("CVE-2009-4631", "CVE-2009-4632", "CVE-2009-4633", "CVE-2009-4634", "CVE-2009-4635", "CVE-2009-4636", "CVE-2009-4637", "CVE-2009-4638", "CVE-2009-4639", "CVE-2009-4640", "CVE-2010-3429", "CVE-2010-3908", "CVE-2010-4704", "CVE-2010-4705", "CVE-2011-1931", "CVE-2011-3362", "CVE-2011-3893", "CVE-2011-3895", "CVE-2011-3929", "CVE-2011-3934", "CVE-2011-3935", "CVE-2011-3936", "CVE-2011-3937", "CVE-2011-3940", "CVE-2011-3941", "CVE-2011-3944", "CVE-2011-3945", "CVE-2011-3946", "CVE-2011-3947", "CVE-2011-3949", "CVE-2011-3950", "CVE-2011-3951", "CVE-2011-3952", "CVE-2011-3973", "CVE-2011-3974", "CVE-2011-4351", "CVE-2011-4352", "CVE-2011-4353", "CVE-2011-4364", "CVE-2012-0947", "CVE-2012-2771", "CVE-2012-2772", "CVE-2012-2773", "CVE-2012-2774", "CVE-2012-2775", "CVE-2012-2776", "CVE-2012-2777", "CVE-2012-2778", "CVE-2012-2779", "CVE-2012-2780", "CVE-2012-2781", "CVE-2012-2782", "CVE-2012-2783", "CVE-2012-2784", "CVE-2012-2785", "CVE-2012-2786", "CVE-2012-2787", "CVE-2012-2788", "CVE-2012-2789", "CVE-2012-2790", "CVE-2012-2791", "CVE-2012-2792", "CVE-2012-2793", "CVE-2012-2794", "CVE-2012-2795", "CVE-2012-2796", "CVE-2012-2797", "CVE-2012-2798", "CVE-2012-2799", "CVE-2012-2800", "CVE-2012-2801", "CVE-2012-2802", "CVE-2012-2803", "CVE-2012-2804", "CVE-2012-2805", "CVE-2013-3670", "CVE-2013-3671", "CVE-2013-3672", "CVE-2013-3673", "CVE-2013-3674", "CVE-2013-3675");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201310-12");
  script_copyright("Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"media-video/ffmpeg", unaffected: make_list("ge 1.0.7"), vulnerable: make_list("lt 1.0.7"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
