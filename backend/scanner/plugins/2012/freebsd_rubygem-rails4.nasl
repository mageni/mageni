###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_rubygem-rails4.nasl 12634 2018-12-04 07:26:26Z cfischer $
#
# Auto generated from VID 31db9a18-e289-11e1-a57d-080027a27dbf
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
  script_oid("1.3.6.1.4.1.25623.1.0.71507");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2012-3463", "CVE-2012-3464", "CVE-2012-3465");
  script_version("$Revision: 12634 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 08:26:26 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
  script_name("FreeBSD Ports: rubygem-rails");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  rubygem-rails, rubygem-actionpack, rubygem-activesupport

CVE-2012-3463
Cross-site scripting (XSS) vulnerability in
actionpack/lib/action_view/helpers/form_tag_helper.rb in Ruby on Rails
3.x before 3.0.17, 3.1.x before 3.1.8, and 3.2.x before 3.2.8 allows
remote attackers to inject arbitrary web script or HTML via the prompt
field to the select_tag helper.
CVE-2012-3464
Cross-site scripting (XSS) vulnerability in
activesupport/lib/active_support/core_ext/string/output_safety.rb in
Ruby on Rails before 3.0.17, 3.1.x before 3.1.8, and 3.2.x before
3.2.8 might allow remote attackers to inject arbitrary web script or
HTML via vectors involving a ' (quote) character.
CVE-2012-3465
Cross-site scripting (XSS) vulnerability in
actionpack/lib/action_view/helpers/sanitize_helper.rb in the
strip_tags helper in Ruby on Rails before 3.0.17, 3.1.x before 3.1.8,
and 3.2.x before 3.2.8 allows remote attackers to inject arbitrary web
script or HTML via malformed HTML markup.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://groups.google.com/d/msg/rubyonrails-security/fV3QUToSMSw/eHBSFOUYHpYJ");
  script_xref(name:"URL", value:"https://groups.google.com/d/msg/rubyonrails-security/kKGNeMrnmiY/r2yM7xy-G48J");
  script_xref(name:"URL", value:"https://groups.google.com/d/msg/rubyonrails-security/FgVEtBajcTY/tYLS1JJTu38J");
  script_xref(name:"URL", value:"http://weblog.rubyonrails.org/2012/8/9/ann-rails-3-2-8-has-been-released/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/31db9a18-e289-11e1-a57d-080027a27dbf.html");

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

bver = portver(pkg:"rubygem-rails");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.8")<0) {
  txt += "Package rubygem-rails version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"rubygem-actionpack");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.8")<0) {
  txt += "Package rubygem-actionpack version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"rubygem-activesupport");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.8")<0) {
  txt += "Package rubygem-activesupport version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}