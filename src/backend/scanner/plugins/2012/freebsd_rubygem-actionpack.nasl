###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_rubygem-actionpack.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID ae2fa87c-4bca-4138-8be1-67ce2a19b3a8
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
  script_oid("1.3.6.1.4.1.25623.1.0.71516");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2012-3424");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
  script_name("FreeBSD Ports: rubygem-actionpack");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: rubygem-actionpack

CVE-2012-3424
The decode_credentials method in
actionpack/lib/action_controller/metal/http_authentication.rb in Ruby
on Rails 3.x before 3.0.16, 3.1.x before 3.1.7, and 3.2.x before 3.2.7
converts Digest Authentication strings to symbols, which allows remote
attackers to cause a denial of service by leveraging access to an
application that uses a with_http_digest helper method, as
demonstrated by the authenticate_or_request_with_http_digest method.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://groups.google.com/forum/?fromgroups#!topic/rubyonrails-security/vxJjrc15qYM");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ae2fa87c-4bca-4138-8be1-67ce2a19b3a8.html");

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

bver = portver(pkg:"rubygem-actionpack");
if(!isnull(bver) && revcomp(a:bver, b:"3.2.7")<0) {
  txt += "Package rubygem-actionpack version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}